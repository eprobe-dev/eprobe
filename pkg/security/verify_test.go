package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Test-only RFC 8032 Section 7.1 Test Vector #1 fixtures (never used in production).
const (
	rfc8032TestSeedHex   = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfc8032TestPubKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

func TestVerifyManifestAndHash(t *testing.T) {
	// 1. Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 2. Mock manifest bytes and signature
	manifestBytes := []byte("name: app/http-tracer\nversion: 1.0.0\nauthor: eprobe-team\n")
	signature := ed25519.Sign(privKey, manifestBytes)

	// 3. Verify valid manifest signature
	err = VerifyManifest(manifestBytes, signature, pubKey)
	if err != nil {
		t.Errorf("expected verification to pass, got: %v", err)
	}

	// 4. Verify invalid manifest signature (tempered data)
	temperedManifest := []byte("name: app/http-tracer\nversion: 2.0.0\nauthor: eprobe-team\n")
	err = VerifyManifest(temperedManifest, signature, pubKey)
	if err == nil {
		t.Error("expected verification to fail for tempered manifest, but it passed")
	}

	// 5. Verify invalid manifest signature (wrong signature bytes)
	badSignature := make([]byte, ed25519.SignatureSize)
	err = VerifyManifest(manifestBytes, badSignature, pubKey)
	if err == nil {
		t.Error("expected verification to fail for wrong signature bytes, but it passed")
	}

	// 6. Test program checksum verification
	programBytes := []byte("mock-ebpf-elf-bytecode-instructions")
	hashBytes := sha256.Sum256(programBytes)
	validHash := hex.EncodeToString(hashBytes[:])

	err = VerifyProgramHash(programBytes, validHash)
	if err != nil {
		t.Errorf("expected checksum verification to pass, got: %v", err)
	}

	// 7. Test program checksum verification (corrupted payload)
	corruptedBytes := []byte("mock-ebpf-elf-bytecode-instructions-corrupted")
	err = VerifyProgramHash(corruptedBytes, validHash)
	if err == nil {
		t.Error("expected checksum verification to fail for corrupted program payload, but it passed")
	}
}

func TestVerifyManifestHybrid(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a hybrid manifest: all lines CRLF except the sha256 line which is LF
	hybridManifest := []byte("name: log/stderr-capture\r\nversion: 1.0.0\r\nsha256: 123456\nauthor: eprobe-team\r\n")
	signature := ed25519.Sign(privKey, hybridManifest)

	// Test 1: Verify hybrid raw manifest
	err = VerifyManifest(hybridManifest, signature, pubKey)
	if err != nil {
		t.Errorf("expected hybrid raw manifest to verify: %v", err)
	}

	// Test 2: Verify same manifest after normalization to LF
	lfNormalized := []byte("name: log/stderr-capture\nversion: 1.0.0\nsha256: 123456\nauthor: eprobe-team\n")
	err = VerifyManifest(lfNormalized, signature, pubKey)
	if err != nil {
		t.Errorf("expected LF normalized manifest to verify against hybrid signature: %v", err)
	}
}

func TestDefaultPublicKeyRotatedAndEnvOverride(t *testing.T) {
	if DefaultPublicKeyHex == rfc8032TestPubKeyHex {
		t.Fatal("DefaultPublicKeyHex must not use RFC 8032 Test Vector #1")
	}

	t.Setenv("EPROBE_PUBLIC_KEY", "")
	defaultKey := GetDefaultPublicKey()
	if len(defaultKey) != ed25519.PublicKeySize {
		t.Fatalf("expected default key length %d, got %d", ed25519.PublicKeySize, len(defaultKey))
	}
	expectedDefaultBytes, err := hex.DecodeString(DefaultPublicKeyHex)
	if err != nil {
		t.Fatalf("invalid DefaultPublicKeyHex: %v", err)
	}
	if !bytes.Equal(defaultKey, expectedDefaultBytes) {
		t.Fatalf("GetDefaultPublicKey() did not return decoded DefaultPublicKeyHex")
	}

	// Sign a manifest using the RFC 8032 test vector seed and confirm the production default key rejects it.
	rfcSeed, err := hex.DecodeString(rfc8032TestSeedHex)
	if err != nil {
		t.Fatalf("failed to decode test seed: %v", err)
	}
	rfcPriv := ed25519.NewKeyFromSeed(rfcSeed)
	manifest := []byte("name: sec/exec-audit\nversion: 1.0.0\n")
	sig := ed25519.Sign(rfcPriv, manifest)

	if err := VerifyManifest(manifest, sig, defaultKey); err == nil {
		t.Fatal("production default key must reject signature produced by RFC 8032 test vector")
	}

	// Setting EPROBE_PUBLIC_KEY overrides the verification key.
	t.Setenv("EPROBE_PUBLIC_KEY", "  "+rfc8032TestPubKeyHex+"  ")
	overrideKey := GetDefaultPublicKey()
	expectedOverrideBytes, _ := hex.DecodeString(rfc8032TestPubKeyHex)
	if !bytes.Equal(overrideKey, expectedOverrideBytes) {
		t.Fatalf("expected override key %x, got %x", expectedOverrideBytes, overrideKey)
	}
	if err := VerifyManifest(manifest, sig, overrideKey); err != nil {
		t.Fatalf("expected VerifyManifest to succeed with EPROBE_PUBLIC_KEY override: %v", err)
	}

	// Invalid hex or wrong-length EPROBE_PUBLIC_KEY safely falls back to DefaultPublicKeyHex.
	for _, badEnv := range []string{"not-valid-hex", "01020304"} {
		t.Setenv("EPROBE_PUBLIC_KEY", badEnv)
		fallback := GetDefaultPublicKey()
		if !bytes.Equal(fallback, expectedDefaultBytes) {
			t.Errorf("expected fallback to DefaultPublicKeyHex for EPROBE_PUBLIC_KEY=%q", badEnv)
		}
	}
}
