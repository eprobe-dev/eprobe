package runtime

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"eprobe/pkg/registry"
)

// ModuleOptions contains optional parameters for loading eBPF modules
type ModuleOptions struct {
	FilterPort      uint16
	FilterPID       uint32
	SlowThresholdUS uint64
	CustomLibSSL    string
	FilterErrors    bool
	DynamicVars     map[string]string
}

// resolveLibSSLPath locates an active libssl.so on the system or validates the custom path.
func resolveLibSSLPath(customPath string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
		return "", fmt.Errorf("specified libssl path %q not found", customPath)
	}

	candidates := []string{
		"/usr/lib64/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib64/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/libssl.so.3",
		"/usr/lib/libssl.so.3",
		"/usr/lib64/libssl.so",
		"/usr/lib/x86_64-linux-gnu/libssl.so",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("unable to auto-discover libssl.so on host (please specify via --libssl <path>)")
}

// LoadedModule holds the references to the active eBPF collection and its hooks
type LoadedModule struct {
	Collection *ebpf.Collection
	Links      []link.Link
	Manifest   *registry.Manifest
}

// Close detaches all hooks and releases the eBPF collection
func (lm *LoadedModule) Close() {
	for _, l := range lm.Links {
		l.Close()
	}
	if lm.Collection != nil {
		lm.Collection.Close()
	}
}

func normalizeFlagKey(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

// ValidateDynamicFlags ensures every dynamic CLI flag supplied by the operator maps to a
// declared variable in manifest.Variables.
func ValidateDynamicFlags(manifest *registry.Manifest, dynamicVars map[string]string) error {
	if len(dynamicVars) == 0 || manifest == nil {
		if len(dynamicVars) > 0 {
			for k := range dynamicVars {
				return fmt.Errorf("unknown flag --%s (module declares no dynamic variables)", k)
			}
		}
		return nil
	}

	allowed := make(map[string]bool, len(manifest.Variables))
	for _, vInfo := range manifest.Variables {
		key := normalizeFlagKey(vInfo.CLIFlag)
		if key == "" {
			key = normalizeFlagKey(vInfo.Name)
		}
		if key != "" {
			allowed[key] = true
		}
	}

	keys := make([]string, 0, len(dynamicVars))
	for k := range dynamicVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if !allowed[normalizeFlagKey(k)] {
			return fmt.Errorf("unknown flag --%s for module %s (run 'eprobe help %s' for supported flags)", k, manifest.Name, manifest.Name)
		}
	}
	return nil
}

func parseVariableValue(raw string, varType string) (interface{}, error) {
	trimmed := strings.TrimSpace(raw)
	normType := strings.ToLower(strings.TrimSpace(varType))

	// Allow boolean-style flag values ("true"/"false") for numeric flags like errors_only
	if strings.HasPrefix(normType, "uint") || strings.HasPrefix(normType, "int") {
		if strings.EqualFold(trimmed, "true") {
			trimmed = "1"
		} else if strings.EqualFold(trimmed, "false") {
			trimmed = "0"
		}
	}

	switch normType {
	case "uint8":
		v, err := strconv.ParseUint(trimmed, 10, 8)
		if err != nil {
			return nil, err
		}
		return uint8(v), nil
	case "uint16":
		v, err := strconv.ParseUint(trimmed, 10, 16)
		if err != nil {
			return nil, err
		}
		return uint16(v), nil
	case "uint32":
		v, err := strconv.ParseUint(trimmed, 10, 32)
		if err != nil {
			return nil, err
		}
		return uint32(v), nil
	case "uint64":
		v, err := strconv.ParseUint(trimmed, 10, 64)
		if err != nil {
			return nil, err
		}
		return uint64(v), nil
	case "int32":
		v, err := strconv.ParseInt(trimmed, 10, 32)
		if err != nil {
			return nil, err
		}
		return int32(v), nil
	case "int64":
		v, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return nil, err
		}
		return int64(v), nil
	case "bool":
		v, err := strconv.ParseBool(trimmed)
		if err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported variable type %q", varType)
	}
}

func castUintValue(val uint64, varType string) (interface{}, error) {
	switch strings.ToLower(strings.TrimSpace(varType)) {
	case "uint8":
		return uint8(val), nil
	case "uint16":
		return uint16(val), nil
	case "uint32":
		return uint32(val), nil
	case "uint64":
		return uint64(val), nil
	case "int32":
		return int32(val), nil
	case "int64":
		return int64(val), nil
	case "bool":
		return val != 0, nil
	default:
		return nil, fmt.Errorf("unsupported variable type %q", varType)
	}
}

// ValidateAndBindVariables validates dynamic CLI flags against manifest.Variables and
// rewrites matching eBPF .rodata constants in spec.Variables.
func ValidateAndBindVariables(spec *ebpf.CollectionSpec, manifest *registry.Manifest, opts ModuleOptions) error {
	if err := ValidateDynamicFlags(manifest, opts.DynamicVars); err != nil {
		return err
	}
	if manifest == nil || spec == nil {
		return nil
	}

	normDyn := make(map[string]string, len(opts.DynamicVars))
	for k, v := range opts.DynamicVars {
		normDyn[normalizeFlagKey(k)] = v
	}

	for _, vInfo := range manifest.Variables {
		flagKey := normalizeFlagKey(vInfo.CLIFlag)
		if flagKey == "" {
			flagKey = normalizeFlagKey(vInfo.Name)
		}

		var boundVal interface{}
		var shouldSet bool

		switch {
		case flagKey == "port" && opts.FilterPort != 0:
			var err error
			boundVal, err = castUintValue(uint64(opts.FilterPort), vInfo.Type)
			if err != nil {
				return fmt.Errorf("invalid type for variable %s: %w", vInfo.Name, err)
			}
			shouldSet = true
		case flagKey == "pid" && opts.FilterPID != 0:
			var err error
			boundVal, err = castUintValue(uint64(opts.FilterPID), vInfo.Type)
			if err != nil {
				return fmt.Errorf("invalid type for variable %s: %w", vInfo.Name, err)
			}
			shouldSet = true
		case (flagKey == "slow-us" || flagKey == "slow") && opts.SlowThresholdUS != 0:
			var err error
			boundVal, err = castUintValue(opts.SlowThresholdUS, vInfo.Type)
			if err != nil {
				return fmt.Errorf("invalid type for variable %s: %w", vInfo.Name, err)
			}
			shouldSet = true
		case flagKey == "errors-only" && opts.FilterErrors:
			var err error
			boundVal, err = castUintValue(1, vInfo.Type)
			if err != nil {
				return fmt.Errorf("invalid type for variable %s: %w", vInfo.Name, err)
			}
			shouldSet = true
		default:
			if rawVal, ok := normDyn[flagKey]; ok {
				var err error
				boundVal, err = parseVariableValue(rawVal, vInfo.Type)
				if err != nil {
					return fmt.Errorf("invalid value %q for --%s (%s): %w", rawVal, flagKey, vInfo.Type, err)
				}
				shouldSet = true
			}
		}

		if shouldSet {
			if v, ok := spec.Variables[vInfo.Name]; ok {
				if err := v.Set(boundVal); err != nil {
					return fmt.Errorf("failed to set variable %s: %w", vInfo.Name, err)
				}
			}
		}
	}

	return nil
}

// LoadModule loads the eBPF ELF binary, performs relocations, and attaches to hooks dynamically using cache manifests.
func LoadModule(name string, opts ModuleOptions) (*LoadedModule, error) {
	return LoadModuleFromDir(registry.GetModulePath(name), opts)
}

// LoadModuleFromDir loads the eBPF ELF binary and manifest directly from modDir.
func LoadModuleFromDir(modDir string, opts ModuleOptions) (*LoadedModule, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("Warning: failed to remove memlock: %v\n", err)
	}

	// 1. Read manifest.yaml dynamically
	manifestPath := filepath.Join(modDir, "manifest.yaml")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read module manifest: %w", err)
	}

	// 2. Parse manifest
	manifest, err := registry.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if len(manifest.AttachPoints) == 0 {
		return nil, fmt.Errorf("no attach points defined in module manifest")
	}

	// 3. Read program.o dynamically
	programPath := filepath.Join(modDir, "program.o")
	elfBytes, err := os.ReadFile(programPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read module program.o: %w", err)
	}

	// 4. Load the collection spec from ELF bytes
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elfBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// 5. Validate and bind dynamic variables into .rodata
	if err := ValidateAndBindVariables(spec, manifest, opts); err != nil {
		return nil, err
	}

	// 6. Load collection into kernel (performs automatic CO-RE relocations against host BTF)
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load ebpf collection into kernel: %w", err)
	}

	lm := &LoadedModule{
		Collection: coll,
		Links:      make([]link.Link, 0),
		Manifest:   manifest,
	}

	// Cache executable handles for uprobes
	execMap := make(map[string]*link.Executable)

	// 7. Attach hooks dynamically matching manifest specifications
	for _, ap := range manifest.AttachPoints {
		prog, ok := coll.Programs[ap.Section]
		if !ok {
			lm.Close()
			return nil, fmt.Errorf("program section %s not found in ELF", ap.Section)
		}

		if ap.Type == "tracepoint" {
			sys := "syscalls"
			hook := ap.Symbol
			if parts := strings.Split(ap.Symbol, "/"); len(parts) == 2 {
				sys = parts[0]
				hook = parts[1]
			} else if parts := strings.Split(ap.Symbol, ":"); len(parts) == 2 {
				sys = parts[0]
				hook = parts[1]
			}
			tp, err := link.Tracepoint(sys, hook, prog, nil)
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to attach tracepoint %s/%s: %w", sys, hook, err)
			}
			lm.Links = append(lm.Links, tp)
		} else if ap.Type == "kprobe" {
			kp, err := link.Kprobe(ap.Symbol, prog, nil)
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to attach kprobe %s: %w", ap.Symbol, err)
			}
			lm.Links = append(lm.Links, kp)
		} else if ap.Type == "raw_tracepoint" {
			rtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    ap.Symbol,
				Program: prog,
			})
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to attach raw_tracepoint %s: %w", ap.Symbol, err)
			}
			lm.Links = append(lm.Links, rtp)
		} else if ap.Type == "uprobe" || ap.Type == "uretprobe" {
			targetLib, err := resolveLibSSLPath(opts.CustomLibSSL)
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to resolve target library for %s (%s): %w", ap.Type, ap.Symbol, err)
			}

			ex, ok := execMap[targetLib]
			if !ok {
				var openErr error
				ex, openErr = link.OpenExecutable(targetLib)
				if openErr != nil {
					lm.Close()
					return nil, fmt.Errorf("failed to open executable %s: %w", targetLib, openErr)
				}
				execMap[targetLib] = ex
			}

			if ap.Type == "uprobe" {
				up, err := ex.Uprobe(ap.Symbol, prog, nil)
				if err != nil {
					// Gracefully skip optional extended symbols like SSL_write_ex on older libssl
					if strings.HasSuffix(ap.Symbol, "_ex") {
						fmt.Printf("Notice: optional uprobe symbol %s not found in %s, skipping\n", ap.Symbol, targetLib)
						continue
					}
					lm.Close()
					return nil, fmt.Errorf("failed to attach uprobe %s in %s: %w", ap.Symbol, targetLib, err)
				}
				lm.Links = append(lm.Links, up)
			} else {
				urp, err := ex.Uretprobe(ap.Symbol, prog, nil)
				if err != nil {
					if strings.HasSuffix(ap.Symbol, "_ex") {
						fmt.Printf("Notice: optional uretprobe symbol %s not found in %s, skipping\n", ap.Symbol, targetLib)
						continue
					}
					lm.Close()
					return nil, fmt.Errorf("failed to attach uretprobe %s in %s: %w", ap.Symbol, targetLib, err)
				}
				lm.Links = append(lm.Links, urp)
			}
		} else {
			lm.Close()
			return nil, fmt.Errorf("unsupported attach point type: %s", ap.Type)
		}
	}

	return lm, nil
}

