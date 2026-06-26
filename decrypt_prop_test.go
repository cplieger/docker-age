package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"pgregory.net/rapid"
)

// Property-based tests (pgregory.net/rapid) for the decrypt paths: encrypt →
// decrypt round-trips (armored and binary), resilient walk over mixed valid /
// invalid inputs, the decompression-bomb output cap, and the plaintext no-op.

// Property 1: Armored encrypt → decrypt produces identical bytes.
func TestProperty_ArmoredRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			rt.Fatalf("generate identity: %v", err)
		}

		numPairs := rapid.IntRange(1, 10).Draw(rt, "numPairs")
		var lines []string
		for i := range numPairs {
			key := rapid.StringMatching(`[A-Z][A-Z0-9_]{0,19}`).Draw(rt, fmt.Sprintf("key_%d", i))
			value := rapid.StringMatching(`[a-zA-Z0-9_\-\./:@=+, ]{0,50}`).Draw(rt, fmt.Sprintf("value_%d", i))
			lines = append(lines, key+"="+value)
		}
		original := []byte(strings.Join(lines, "\n") + "\n")

		tmpDir, err := os.MkdirTemp("", "age-roundtrip-*")
		if err != nil {
			rt.Fatalf("mkdtemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		encrypted, err := encryptArmored(original, identity.Recipient())
		if err != nil {
			rt.Fatalf("encrypt: %v", err)
		}
		envPath := filepath.Join(tmpDir, "test.env")
		if err := os.WriteFile(envPath, encrypted, 0o644); err != nil {
			rt.Fatalf("write: %v", err)
		}

		count, err := decryptAllCount(tmpDir, identity)
		if err != nil {
			rt.Fatalf("decryptAll: %v", err)
		}
		if count != 1 {
			rt.Fatalf("count = %d, want 1", count)
		}

		decrypted, err := os.ReadFile(envPath)
		if err != nil {
			rt.Fatalf("read decrypted: %v", err)
		}
		if !bytes.Equal(decrypted, original) {
			rt.Fatalf("mismatch:\n  original:  %q\n  decrypted: %q", original, decrypted)
		}
	})
}

// Property 2: Binary-encrypted files are also decrypted in place.
func TestProperty_BinaryRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			rt.Fatalf("generate identity: %v", err)
		}

		// Draw random content to verify binary format handles arbitrary bytes.
		numPairs := rapid.IntRange(1, 10).Draw(rt, "numPairs")
		var lines []string
		for i := range numPairs {
			key := rapid.StringMatching(`[A-Z][A-Z0-9_]{0,19}`).Draw(rt, fmt.Sprintf("key_%d", i))
			value := rapid.StringMatching(`[a-zA-Z0-9_\-\./:@=+, ]{0,50}`).Draw(rt, fmt.Sprintf("value_%d", i))
			lines = append(lines, key+"="+value)
		}
		original := []byte(strings.Join(lines, "\n") + "\n")

		encrypted, err := encryptBinary(original, identity.Recipient())
		if err != nil {
			rt.Fatalf("encrypt: %v", err)
		}

		tmpDir, err := os.MkdirTemp("", "age-binary-*")
		if err != nil {
			rt.Fatalf("mkdtemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		envPath := filepath.Join(tmpDir, "test.env")
		if err := os.WriteFile(envPath, encrypted, 0o644); err != nil {
			rt.Fatalf("write: %v", err)
		}

		count, err := decryptAllCount(tmpDir, identity)
		if err != nil {
			rt.Fatalf("decryptAll: %v", err)
		}
		if count != 1 {
			rt.Fatalf("count = %d, want 1", count)
		}

		decrypted, err := os.ReadFile(envPath)
		if err != nil {
			rt.Fatalf("read: %v", err)
		}
		if !bytes.Equal(decrypted, original) {
			rt.Fatalf("mismatch:\n  original:  %q\n  decrypted: %q", original, decrypted)
		}
	})
}

// Property 3: Valid files decrypt in place, invalid files are skipped.
func TestProperty_ResilientWalk(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			rt.Fatalf("generate identity: %v", err)
		}

		tmpDir, err := os.MkdirTemp("", "age-resilient-*")
		if err != nil {
			rt.Fatalf("mkdtemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		// Create valid encrypted .env files (some in subdirectories)
		numValid := rapid.IntRange(1, 5).Draw(rt, "numValid")
		type validFile struct {
			path    string
			content []byte
		}
		validFiles := make([]validFile, 0, numValid)
		for i := range numValid {
			content := fmt.Appendf(nil, "KEY_%d=value_%d\n", i, i)
			encrypted, encErr := encryptArmored(content, identity.Recipient())
			if encErr != nil {
				rt.Fatalf("encrypt %d: %v", i, encErr)
			}
			dir := tmpDir
			if i%2 == 1 {
				dir = filepath.Join(tmpDir, fmt.Sprintf("sub%d", i))
				_ = os.MkdirAll(dir, 0o755)
			}
			p := filepath.Join(dir, fmt.Sprintf("valid%d.env", i))
			_ = os.WriteFile(p, encrypted, 0o644)
			validFiles = append(validFiles, validFile{path: p, content: content})
		}

		// Create invalid .env files that should be skipped
		numInvalid := rapid.IntRange(1, 5).Draw(rt, "numInvalid")
		type invalidFile struct {
			path string
			data []byte
		}
		invalidFiles := make([]invalidFile, 0, numInvalid)
		for i := range numInvalid {
			p := filepath.Join(tmpDir, fmt.Sprintf("invalid%d.env", i))
			kind := rapid.SampledFrom([]string{"plaintext", "empty", "binary"}).Draw(rt, fmt.Sprintf("kind_%d", i))
			var data []byte
			switch kind {
			case "plaintext":
				data = []byte("PLAIN=value\n")
			case "empty":
				data = []byte{}
			case "binary":
				data = rapid.SliceOfN(rapid.Byte(), 10, 200).Draw(rt, fmt.Sprintf("garbage_%d", i))
			}
			_ = os.WriteFile(p, data, 0o644)
			invalidFiles = append(invalidFiles, invalidFile{path: p, data: data})
		}

		// Non-.env files should be ignored entirely
		_ = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("ignored"), 0o644)

		count, err := decryptAllCount(tmpDir, identity)
		if err != nil {
			rt.Fatalf("decryptAll error: %v", err)
		}
		if count != numValid {
			rt.Fatalf("count = %d, want %d", count, numValid)
		}

		for _, vf := range validFiles {
			got, err := os.ReadFile(vf.path)
			if err != nil {
				rt.Fatalf("read decrypted: %v", err)
			}
			if !bytes.Equal(got, vf.content) {
				rt.Fatalf("mismatch for %s:\n  want: %q\n  got:  %q", vf.path, vf.content, got)
			}
		}

		for _, inf := range invalidFiles {
			got, err := os.ReadFile(inf.path)
			if err != nil {
				rt.Fatalf("read invalid: %v", err)
			}
			if !bytes.Equal(got, inf.data) {
				rt.Fatalf("invalid file %s was modified", inf.path)
			}
		}
	})
}

// Property 4: Oversized decrypted content is rejected (decompression bomb guard).
func TestProperty_OversizedDecryptedContent(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create a 2 MB plaintext (exceeds the 1 MB limit)
	bigContent := bytes.Repeat([]byte("A"), 2<<20)
	encrypted, err := encryptArmored(bigContent, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	envPath := filepath.Join(tmpDir, "big.env")
	if err := os.WriteFile(envPath, encrypted, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 (oversized file should be skipped)", count)
	}

	// File should remain encrypted (not overwritten)
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(armoredHeader)) {
		t.Error("oversized file should not have been overwritten")
	}
}

// Property: decrypting a plaintext .env file is always a no-op (file unchanged).
func TestProperty_DecryptFile_plaintext_is_noop(t *testing.T) {
	identity := newIdentity(t)

	rapid.Check(t, func(rt *rapid.T) {
		tmpDir, err := os.MkdirTemp("", "age-noop-*")
		if err != nil {
			rt.Fatalf("mkdtemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		// Generate random plaintext .env content that doesn't start with age headers
		numPairs := rapid.IntRange(1, 5).Draw(rt, "numPairs")
		var lines []string
		for i := range numPairs {
			key := rapid.StringMatching(`[A-Z][A-Z0-9_]{0,9}`).Draw(rt, fmt.Sprintf("key_%d", i))
			value := rapid.StringMatching(`[a-zA-Z0-9_\-]{0,20}`).Draw(rt, fmt.Sprintf("val_%d", i))
			lines = append(lines, key+"="+value)
		}
		content := []byte(strings.Join(lines, "\n") + "\n")

		envPath := filepath.Join(tmpDir, "plain.env")
		if err := os.WriteFile(envPath, content, 0o644); err != nil {
			rt.Fatalf("write: %v", err)
		}

		rootDir, openErr := os.OpenRoot(tmpDir)
		if openErr != nil {
			rt.Fatalf("OpenRoot: %v", openErr)
		}
		defer func() { _ = rootDir.Close() }()

		got := decryptFileBool(rootDir, "plain.env", identity)
		if got {
			rt.Fatal("decryptFile(plaintext) = true, want false")
		}

		// File must be unchanged
		after, readErr := os.ReadFile(envPath)
		if readErr != nil {
			rt.Fatalf("read: %v", readErr)
		}
		if !bytes.Equal(after, content) {
			rt.Fatalf("plaintext file was modified: got %q, want %q", after, content)
		}
	})
}
