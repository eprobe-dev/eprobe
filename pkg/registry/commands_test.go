package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"eprobe/pkg/security"
)

func TestCLICommandsWorkflow(t *testing.T) {
	// 1. Generate Ed25519 keys
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 2. Prepare test mock program
	programData := []byte("test-ebpf-object-code")
	hashBytes := sha256.Sum256(programData)
	expectedHash := hex.EncodeToString(hashBytes[:])

	// 3. Prepare test manifest and sign it
	manifest := "name: test/mock-module\nversion: 1.0.0\nauthor: test-author\nsha256: " + expectedHash + "\n"
	signature := ed25519.Sign(privKey, []byte(manifest))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// 4. Create compressed package archive (.epm) in memory
	var archiveBuf bytes.Buffer
	gw := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gw)

	files := map[string][]byte{
		"manifest.yaml": []byte(manifest),
		"manifest.sig":  signature,
		"program.o":     programData,
	}
	for name, data := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("failed to write body: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()

	// 5. Spin up test registry server mock
	registryInfo := ModuleInfo{
		Name:        "test/mock-module",
		Version:     "1.0.0",
		Author:      "test-author",
		Manifest:    manifest,
		Signature:   signatureB64,
		DownloadURL: "/v1/modules/test/mock-module/download",
	}

	catalogResponse := CatalogResponse{
		Modules: []ModuleInfo{
			{
				Name:        "test/mock-module",
				Version:     "1.0.0",
				Author:      "test-author",
				Description: "A test mock module",
				DownloadURL: "/v1/modules/test/mock-module/download",
			},
		},
		Total: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/modules/test/mock-module":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(registryInfo)
		case "/v1/modules/test/mock-module/download":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(archiveBuf.Bytes())
		case "/v1/modules":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(catalogResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// 6. Set temporary local cache folder for testing to keep system directories untouched
	tmpCacheDir, err := os.MkdirTemp("", "eprobe-commands-test-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpCacheDir)

	// Inject the custom cache directory
	CustomCacheDir = tmpCacheDir
	defer func() { CustomCacheDir = "" }()

	// 7. Verify list is empty initially
	if IsModuleCached("test/mock-module") {
		t.Error("expected test module not to be cached initially")
	}

	// 8. Pull module from mock registry server
	err = PullModule(context.Background(), "test/mock-module", server.URL, pubKey)
	if err != nil {
		t.Fatalf("expected PullModule to succeed, got: %v", err)
	}

	// 9. Verify cached assets exist
	if !IsModuleCached("test/mock-module") {
		t.Error("expected test module to be cached after PullModule")
	}

	// 10. Run ListModules (should print list to stdout)
	err = ListModules()
	if err != nil {
		t.Errorf("ListModules failed: %v", err)
	}

	// 11. Run DescribeModule (should print manifest to stdout)
	err = DescribeModule("test/mock-module")
	if err != nil {
		t.Errorf("DescribeModule failed: %v", err)
	}

	// 12. Run UpdateModule (should output already up-to-date)
	err = UpdateModule(context.Background(), "test/mock-module", server.URL, pubKey)
	if err != nil {
		t.Errorf("UpdateModule failed: %v", err)
	}

	// 13. Run SearchRemoteModules (should print catalog from registry)
	err = SearchRemoteModules(context.Background(), server.URL)
	if err != nil {
		t.Errorf("SearchRemoteModules failed: %v", err)
	}

	// 14. Run RemoveModule and verify files cleaned up
	err = RemoveModule("test/mock-module")
	if err != nil {
		t.Fatalf("expected RemoveModule to succeed, got: %v", err)
	}

	if IsModuleCached("test/mock-module") {
		t.Error("expected test module to be removed after RemoveModule")
	}
}

func TestCommandsModuleNameValidation(t *testing.T) {
	// Verify that commands reject invalid module names
	err := DescribeModule("../../etc/passwd")
	if err == nil {
		t.Error("expected DescribeModule to reject path traversal name")
	}

	err = RemoveModule("../../etc/passwd")
	if err == nil {
		t.Error("expected RemoveModule to reject path traversal name")
	}
}

func TestPullModuleWithEnvPublicKeyOverride(t *testing.T) {
	// Test-only RFC 8032 Section 7.1 Test Vector #1 fixture (isolated in test code).
	const testSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	const testPubKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Fatalf("failed to decode test seed: %v", err)
	}
	privKey := ed25519.NewKeyFromSeed(seed)

	programData := []byte("test-ebpf-object-code-override")
	hashBytes := sha256.Sum256(programData)
	expectedHash := hex.EncodeToString(hashBytes[:])

	manifest := "name: test/override-module\nversion: 1.0.0\nauthor: test-author\nsha256: " + expectedHash + "\n"
	signature := ed25519.Sign(privKey, []byte(manifest))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	var archiveBuf bytes.Buffer
	gw := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gw)
	files := map[string][]byte{
		"manifest.yaml": []byte(manifest),
		"manifest.sig":  signature,
		"program.o":     programData,
	}
	for name, data := range files {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("failed to write body: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()

	registryInfo := ModuleInfo{
		Name:        "test/override-module",
		Version:     "1.0.0",
		Author:      "test-author",
		Manifest:    manifest,
		Signature:   signatureB64,
		DownloadURL: "/v1/modules/test/override-module/download",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/modules/test/override-module":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(registryInfo)
		case "/v1/modules/test/override-module/download":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archiveBuf.Bytes())
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tmpCacheDir := t.TempDir()
	CustomCacheDir = tmpCacheDir
	defer func() { CustomCacheDir = "" }()

	// Without EPROBE_PUBLIC_KEY override, the production default key rejects the test vector signature.
	t.Setenv("EPROBE_PUBLIC_KEY", "")
	if err := PullModule(context.Background(), "test/override-module", server.URL, security.GetDefaultPublicKey()); err == nil {
		t.Fatal("expected PullModule to fail verification with production default key")
	}

	// With EPROBE_PUBLIC_KEY override set, PullModule succeeds.
	t.Setenv("EPROBE_PUBLIC_KEY", testPubKeyHex)
	if err := PullModule(context.Background(), "test/override-module", server.URL, security.GetDefaultPublicKey()); err != nil {
		t.Fatalf("expected PullModule to succeed with EPROBE_PUBLIC_KEY override, got: %v", err)
	}
}

func TestPrepareLocalModule(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	programData := []byte("local-ebpf-object-bytes")
	sum := sha256.Sum256(programData)
	programSha := hex.EncodeToString(sum[:])
	manifestYAML := "name: sys/syscall-xray\nversion: 1.0.0\nauthor: test\nsha256: " + programSha + "\n"
	sig := ed25519.Sign(privKey, []byte(manifestYAML))

	buildEPM := func(files map[string][]byte) string {
		t.Helper()
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		for name, data := range files {
			hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		_ = tw.Close()
		_ = gw.Close()
		epmPath := filepath.Join(t.TempDir(), "test.epm")
		if err := os.WriteFile(epmPath, buf.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
		return epmPath
	}

	// 1. Signed .epm passes signature & SHA256
	signedPath := buildEPM(map[string][]byte{
		"manifest.yaml": []byte(manifestYAML),
		"manifest.sig":  sig,
		"program.o":     programData,
	})
	dir, manifest, cleanup, err := PrepareLocalModule(signedPath, pubKey)
	if err != nil {
		t.Fatalf("expected signed local module to succeed, got: %v", err)
	}
	if manifest.Name != "sys/syscall-xray" {
		t.Errorf("unexpected manifest name: %q", manifest.Name)
	}
	if _, err := os.Stat(filepath.Join(dir, "program.o")); err != nil {
		t.Errorf("expected extracted program.o: %v", err)
	}
	cleanup()

	// 2. Unsigned .epm verifies SHA256 without manifest.sig
	unsignedPath := buildEPM(map[string][]byte{
		"manifest.yaml": []byte(manifestYAML),
		"program.o":     programData,
	})
	dir, _, cleanup, err = PrepareLocalModule(unsignedPath, pubKey)
	if err != nil {
		t.Fatalf("expected unsigned local module with valid sha256 to succeed, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); err != nil {
		t.Errorf("expected extracted manifest.yaml: %v", err)
	}
	cleanup()

	// 3. Unsigned .epm with tampered program.o fails SHA256 check
	tamperedPath := buildEPM(map[string][]byte{
		"manifest.yaml": []byte(manifestYAML),
		"program.o":     []byte("tampered-bytecode"),
	})
	if _, _, _, err := PrepareLocalModule(tamperedPath, pubKey); err == nil {
		t.Fatal("expected tampered unsigned local module to fail SHA256 verification")
	}

	// 4. Signed .epm with wrong public key fails signature verification
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, _, err := PrepareLocalModule(signedPath, otherPub); err == nil {
		t.Fatal("expected wrong public key to fail signature verification")
	}

	// 5. Unpacked local directory works without tarball extraction
	unpackedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(unpackedDir, "manifest.yaml"), []byte(manifestYAML), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unpackedDir, "program.o"), programData, 0644); err != nil {
		t.Fatal(err)
	}
	dir, mDir, cleanup, err := PrepareLocalModule(unpackedDir, pubKey)
	if err != nil {
		t.Fatalf("expected unpacked directory to succeed, got: %v", err)
	}
	if dir != unpackedDir || mDir.Name != "sys/syscall-xray" {
		t.Errorf("unexpected unpacked result dir=%q name=%q", dir, mDir.Name)
	}
	cleanup()
}
