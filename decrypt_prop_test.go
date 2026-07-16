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
// decrypt round-trips into the plaintext sibling (armored and binary), source
// preservation, resilient walk over mixed valid / invalid sources, the
// decompression-bomb output cap, and the plaintext-output no-op.

// drawEnvContent draws random .env-shaped plaintext.
func drawEnvContent(rt *rapid.T, maxPairs int) []byte {
	numPairs := rapid.IntRange(1, maxPairs).Draw(rt, "numPairs")
	var lines []string
	for i := range numPairs {
		key := rapid.StringMatching(`[A-Z][A-Z0-9_]{0,19}`).Draw(rt, fmt.Sprintf("key_%d", i))
		value := rapid.StringMatching(`[a-zA-Z0-9_\-\./:@=+, ]{0,50}`).Draw(rt, fmt.Sprintf("value_%d", i))
		lines = append(lines, key+"="+value)
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// Property 1: Armored encrypt → decrypt produces identical bytes at the
// sibling output, and the ciphertext source survives byte-for-byte.
func TestProperty_ArmoredRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			rt.Fatalf("generate identity: %v", err)
		}
		original := drawEnvContent(rt, 10)

		tmpDir, err := os.MkdirTemp("", "age-roundtrip-*")
		if err != nil {
			rt.Fatalf("mkdtemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		encrypted, err := encryptArmored(original, identity.Recipient())
		if err != nil {
			rt.Fatalf("encrypt: %v", err)
		}
		srcPath := filepath.Join(tmpDir, "test.env"+encSuffix)
		if err := os.WriteFile(srcPath, encrypted, 0o644); err != nil {
			rt.Fatalf("write: %v", err)
		}

		count, err := decryptAllCount(tmpDir, identity)
		if err != nil {
			rt.Fatalf("decryptAll: %v", err)
		}
		if count != 1 {
			rt.Fatalf("count = %d, want 1", count)
		}

		decrypted, err := os.ReadFile(filepath.Join(tmpDir, "test.env"))
		if err != nil {
			rt.Fatalf("read decrypted: %v", err)
		}
		if !bytes.Equal(decrypted, original) {
			rt.Fatalf("mismatch:\n  original:  %q\n  decrypted: %q", original, decrypted)
		}
		srcAfter, err := os.ReadFile(srcPath)
		if err != nil {
			rt.Fatalf("read source: %v", err)
		}
		if !bytes.Equal(srcAfter, encrypted) {
			rt.Fatal("ciphertext source was modified by the decrypt pass")
		}
	})
}

// Property 2: Binary-encrypted sources also decrypt to the sibling, source
// preserved.
func TestProperty_BinaryRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			rt.Fatalf("generate identity: %v", err)
		}
		original := drawEnvContent(rt, 10)

		encrypted, err := encryptBinary(original, identity.Recipient())
		if err != nil {
			rt.Fatalf("encrypt: %v", err)
		}

		tmpDir, err := os.MkdirTemp("", "age-binary-*")
		if err != nil {
			rt.Fatalf("mkdtemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		srcPath := filepath.Join(tmpDir, "test.env"+encSuffix)
		if err := os.WriteFile(srcPath, encrypted, 0o644); err != nil {
			rt.Fatalf("write: %v", err)
		}

		count, err := decryptAllCount(tmpDir, identity)
		if err != nil {
			rt.Fatalf("decryptAll: %v", err)
		}
		if count != 1 {
			rt.Fatalf("count = %d, want 1", count)
		}

		decrypted, err := os.ReadFile(filepath.Join(tmpDir, "test.env"))
		if err != nil {
			rt.Fatalf("read: %v", err)
		}
		if !bytes.Equal(decrypted, original) {
			rt.Fatalf("mismatch:\n  original:  %q\n  decrypted: %q", original, decrypted)
		}
		srcAfter, err := os.ReadFile(srcPath)
		if err != nil {
			rt.Fatalf("read source: %v", err)
		}
		if !bytes.Equal(srcAfter, encrypted) {
			rt.Fatal("ciphertext source was modified by the decrypt pass")
		}
	})
}

// Property 3: Valid sources decrypt to their siblings; invalid .enc sources
// (plaintext, empty, garbage) fail without being modified and without
// producing any output sibling.
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

		// Valid encrypted sources (some in subdirectories).
		numValid := rapid.IntRange(1, 5).Draw(rt, "numValid")
		type validFile struct {
			src     string
			out     string
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
			out := filepath.Join(dir, fmt.Sprintf("valid%d.env", i))
			src := out + encSuffix
			_ = os.WriteFile(src, encrypted, 0o644)
			validFiles = append(validFiles, validFile{src: src, out: out, content: content})
		}

		// Invalid .enc sources: fail, never modified, no sibling produced.
		numInvalid := rapid.IntRange(1, 5).Draw(rt, "numInvalid")
		type invalidFile struct {
			src  string
			out  string
			data []byte
		}
		invalidFiles := make([]invalidFile, 0, numInvalid)
		for i := range numInvalid {
			out := filepath.Join(tmpDir, fmt.Sprintf("invalid%d.env", i))
			src := out + encSuffix
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
			// Guard against rapid drawing bytes that happen to start with a
			// real age header (astronomically unlikely; cheap to exclude).
			if detectAgeFormat(data) != notAgeFormat {
				data = append([]byte("x"), data...)
			}
			_ = os.WriteFile(src, data, 0o644)
			invalidFiles = append(invalidFiles, invalidFile{src: src, out: out, data: data})
		}

		// Non-.enc files are ignored entirely.
		_ = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("ignored"), 0o644)

		result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
		if err != nil {
			rt.Fatalf("decryptAll error: %v", err)
		}
		if result.Decrypted != numValid {
			rt.Fatalf("Decrypted = %d, want %d", result.Decrypted, numValid)
		}
		if result.Failed != numInvalid {
			rt.Fatalf("Failed = %d, want %d (invalid .enc sources)", result.Failed, numInvalid)
		}

		for _, vf := range validFiles {
			got, err := os.ReadFile(vf.out)
			if err != nil {
				rt.Fatalf("read decrypted: %v", err)
			}
			if !bytes.Equal(got, vf.content) {
				rt.Fatalf("mismatch for %s:\n  want: %q\n  got:  %q", vf.out, vf.content, got)
			}
		}

		for _, inf := range invalidFiles {
			got, err := os.ReadFile(inf.src)
			if err != nil {
				rt.Fatalf("read invalid: %v", err)
			}
			if !bytes.Equal(got, inf.data) {
				rt.Fatalf("invalid source %s was modified", inf.src)
			}
			if _, err := os.Stat(inf.out); err == nil {
				rt.Fatalf("invalid source %s produced an output sibling", inf.src)
			}
		}
	})
}

// Property 4: Oversized decrypted content is rejected (decompression bomb
// guard) — no output sibling, source preserved.
func TestProperty_OversizedDecryptedContent(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// A 2 MB plaintext (exceeds the 1 MB output limit).
	bigContent := bytes.Repeat([]byte("A"), 2<<20)
	encrypted, err := encryptArmored(bigContent, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	srcPath := filepath.Join(tmpDir, "big.env"+encSuffix)
	if err := os.WriteFile(srcPath, encrypted, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 || result.Failed != 1 {
		t.Fatalf("Decrypted=%d Failed=%d, want 0 and 1 (oversized output)", result.Decrypted, result.Failed)
	}
	assertNoOutput(t, filepath.Join(tmpDir, "big.env"))
	assertSourcePreserved(t, srcPath, encrypted)
}

// Property: under --ext, a plaintext file at the output path (the generated
// sibling of a previous pass, or a committed plaintext config) is always a
// no-op skip — never modified, never failed.
func TestProperty_PlaintextOutput_is_noop(t *testing.T) {
	identity := newIdentity(t)

	rapid.Check(t, func(rt *rapid.T) {
		tmpDir, err := os.MkdirTemp("", "age-noop-*")
		if err != nil {
			rt.Fatalf("mkdtemp: %v", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		content := drawEnvContent(rt, 5)
		outPath := filepath.Join(tmpDir, "plain.env")
		if err := os.WriteFile(outPath, content, 0o644); err != nil {
			rt.Fatalf("write: %v", err)
		}

		result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, []string{".env"})
		if err != nil {
			rt.Fatalf("decryptAll: %v", err)
		}
		if result.Skipped != 1 || result.Failed != 0 || result.Decrypted != 0 {
			rt.Fatalf("result = %+v, want Skipped=1 only", result)
		}

		after, readErr := os.ReadFile(outPath)
		if readErr != nil {
			rt.Fatalf("read: %v", readErr)
		}
		if !bytes.Equal(after, content) {
			rt.Fatalf("plaintext output was modified: got %q, want %q", after, content)
		}
	})
}
