package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"eprobe/pkg/registry"
)

func calcSchemaByteLen(schema []registry.FieldSchema) int {
	total := 0
	for _, f := range schema {
		switch f.Type {
		case "uint8":
			total += 1
		case "uint16":
			total += 2
		case "uint32", "ipv4":
			total += 4
		case "uint64":
			total += 8
		case "ipv6":
			total += 16
		case "string":
			total += f.Length
		}
	}
	return total
}

func readDistEPM(t *testing.T, epmPath string) (manifestBytes, objBytes []byte) {
	t.Helper()
	f, err := os.Open(epmPath)
	if err != nil {
		t.Fatalf("failed to open %s: %v", epmPath, err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to open gzip %s: %v", epmPath, err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar error in %s: %v", epmPath, err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read error %s in %s: %v", hdr.Name, epmPath, err)
		}
		switch hdr.Name {
		case "manifest.yaml":
			manifestBytes = data
		case "program.o":
			objBytes = data
		}
	}
	return manifestBytes, objBytes
}

func TestValidateAndBindVariablesStallTracerAndInvalidFlag(t *testing.T) {
	epmPath := filepath.Join("..", "..", "..", "eprobe-modules", "dist", "perf-stall-tracer.epm")
	if _, err := os.Stat(epmPath); os.IsNotExist(err) {
		t.Skip("skipping ELF binding test: ../eprobe-modules/dist/perf-stall-tracer.epm not built")
	}

	manifestBytes, objBytes := readDistEPM(t, epmPath)
	manifest, err := registry.ParseManifest(manifestBytes)
	if err != nil {
		t.Fatalf("ParseManifest failed: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader failed: %v", err)
	}

	opts := ModuleOptions{
		DynamicVars: map[string]string{
			"stall-type":      "1",
			"threshold-ms":    "50",
			"filter-kthreads": "0",
		},
	}
	if err := ValidateAndBindVariables(spec, manifest, opts); err != nil {
		t.Fatalf("ValidateAndBindVariables failed: %v", err)
	}

	var gotStallType, gotFilterKthreads uint32
	var gotThresholdMS uint64
	if err := spec.Variables["filter_stall_type"].Get(&gotStallType); err != nil {
		t.Fatalf("failed to read filter_stall_type: %v", err)
	}
	if err := spec.Variables["threshold_ms"].Get(&gotThresholdMS); err != nil {
		t.Fatalf("failed to read threshold_ms: %v", err)
	}
	if err := spec.Variables["filter_kthreads"].Get(&gotFilterKthreads); err != nil {
		t.Fatalf("failed to read filter_kthreads: %v", err)
	}

	if gotStallType != 1 {
		t.Errorf("expected filter_stall_type=1, got %d", gotStallType)
	}
	if gotThresholdMS != 50 {
		t.Errorf("expected threshold_ms=50, got %d", gotThresholdMS)
	}
	if gotFilterKthreads != 0 {
		t.Errorf("expected filter_kthreads=0, got %d", gotFilterKthreads)
	}

	// Genuinely invalid flag must be rejected and cite eprobe help <module>
	badOpts := ModuleOptions{
		DynamicVars: map[string]string{
			"not-a-real-flag": "123",
		},
	}
	err = ValidateAndBindVariables(spec, manifest, badOpts)
	if err == nil {
		t.Fatal("expected invalid dynamic flag error, got nil")
	}
	if !strings.Contains(err.Error(), "eprobe help perf/stall-tracer") {
		t.Errorf("expected error to cite 'eprobe help perf/stall-tracer', got: %v", err)
	}
}

func TestValidateDynamicFlagsWithoutELF(t *testing.T) {
	manifest := &registry.Manifest{
		Name: "sys/syscall-xray",
		Variables: []registry.Variable{
			{Name: "filter_pid", Type: "uint32", CLIFlag: "pid"},
			{Name: "errors_only", Type: "uint8", CLIFlag: "errors-only"},
			{Name: "slow_threshold_us", Type: "uint64", CLIFlag: "slow-us"},
			{Name: "include_transient", Type: "uint8", CLIFlag: "include-transient"},
		},
	}

	if err := ValidateDynamicFlags(manifest, map[string]string{"include-transient": "1"}); err != nil {
		t.Fatalf("expected valid flag to pass: %v", err)
	}
	err := ValidateDynamicFlags(manifest, map[string]string{"unknown-opt": "1"})
	if err == nil || !strings.Contains(err.Error(), "eprobe help sys/syscall-xray") {
		t.Errorf("expected error citing eprobe help sys/syscall-xray, got: %v", err)
	}
}

func TestAllModulesBTFSpecAndDynamicVariables(t *testing.T) {
	distDir := filepath.Join("..", "..", "..", "eprobe-modules", "dist")
	matches, err := filepath.Glob(filepath.Join(distDir, "*.epm"))
	if err != nil || len(matches) == 0 {
		t.Skip("skipping 8-module ELF/BTF validation: ../eprobe-modules/dist/*.epm not found")
	}

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		if _, err := btf.LoadKernelSpec(); err != nil {
			t.Fatalf("btf.LoadKernelSpec() failed on host /sys/kernel/btf/vmlinux: %v", err)
		}
	}

	for _, epmPath := range matches {
		t.Run(filepath.Base(epmPath), func(t *testing.T) {
			manifestBytes, objBytes := readDistEPM(t, epmPath)
			manifest, err := registry.ParseManifest(manifestBytes)
			if err != nil {
				t.Fatalf("ParseManifest failed: %v", err)
			}

			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
			if err != nil {
				t.Fatalf("LoadCollectionSpecFromReader failed: %v", err)
			}

			// Verify every attach_point section exists in ELF
			for _, ap := range manifest.AttachPoints {
				if _, ok := spec.Programs[ap.Section]; !ok {
					t.Errorf("attach_point section %q missing from ELF programs", ap.Section)
				}
			}

			// Verify every exported map exists and hash key/value byte sizes match schema
			for _, m := range manifest.Maps {
				mSpec, ok := spec.Maps[m.Name]
				if !ok {
					t.Errorf("map %q missing from ELF maps", m.Name)
					continue
				}
				if m.Type == "hash" {
					expectedKey := calcSchemaByteLen(m.KeySchema)
					expectedVal := calcSchemaByteLen(m.ValueSchema)
					if int(mSpec.KeySize) != expectedKey {
						t.Errorf("map %s key size mismatch: ELF=%d manifest=%d", m.Name, mSpec.KeySize, expectedKey)
					}
					if int(mSpec.ValueSize) != expectedVal {
						t.Errorf("map %s value size mismatch: ELF=%d manifest=%d", m.Name, mSpec.ValueSize, expectedVal)
					}
				}
			}

			// Verify every kernel variable in manifest exists in spec.Variables and binds cleanly
			// (comm/host/libssl/sanitize in universal-tls-sniffer are userspace-only flags).
			dynVars := make(map[string]string)
			for _, v := range manifest.Variables {
				if v.Type == "string" || v.CLIFlag == "sanitize" {
					continue
				}
				if _, ok := spec.Variables[v.Name]; !ok {
					t.Errorf("variable %q (flag --%s) not found in ELF .rodata spec.Variables", v.Name, v.CLIFlag)
					continue
				}
				if v.CLIFlag != "" && v.CLIFlag != "pid" && v.CLIFlag != "port" && v.CLIFlag != "slow-us" && v.CLIFlag != "errors-only" {
					dynVars[v.CLIFlag] = "1"
				}
			}
			if err := ValidateAndBindVariables(spec, manifest, ModuleOptions{
				FilterPID:       1234,
				FilterPort:      8080,
				SlowThresholdUS: 10000,
				FilterErrors:    true,
				DynamicVars:     dynVars,
			}); err != nil {
				t.Errorf("ValidateAndBindVariables failed: %v", err)
			}
		})
	}
}
