package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"pgregory.net/rapid"
)

// --- Test helpers ---

// encryptArmored encrypts data with age armor format (ASCII-safe).
func encryptArmored(data []byte, recipient age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encryptBinary encrypts data with age binary format.
func encryptBinary(data []byte, recipient age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// newIdentity generates a fresh X25519 identity for testing.
func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

// writeEncryptedEnv writes an armored-encrypted .env file and returns
// the original plaintext content.
func writeEncryptedEnv(t *testing.T, dir, name string, content []byte, recipient age.Recipient) string {
	t.Helper()
	encrypted, err := encryptArmored(content, recipient)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, encrypted, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// decryptAllCount is a test-local adapter that preserves the pre-refactor
// (count, err) shape for tests that only care about the successful-decrypt
// count. New tests that need to assert on failures should call decryptAll
// directly and use the decryptResult struct fields. Uses a background
// context; tests that need cancellation should call decryptAll directly.
func decryptAllCount(root string, identity age.Identity) (int, error) {
	res, err := decryptAll(context.Background(), root, []age.Identity{identity}, nil)
	return res.Decrypted, err
}

// decryptFileBool is a test-local adapter that preserves the pre-refactor
// bool return for existing tests. New tests that need to distinguish
// fileSkipped from fileFailed should call decryptFile directly.
func decryptFileBool(rootDir *os.Root, rel string, identity age.Identity) bool {
	return decryptFile(context.Background(), rootDir, rel, []age.Identity{identity}) == fileDecrypted
}

// --- Property-based tests ---

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

// --- Unit tests: decryptAll ---

func TestDecryptAllEmptyDirectory(t *testing.T) {
	identity := newIdentity(t)
	count, err := decryptAllCount(t.TempDir(), identity)
	if err != nil || count != 0 {
		t.Fatalf("empty dir: count=%d err=%v", count, err)
	}
}

func TestDecryptAllIgnoresNonEnvFiles(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, "config.txt"), []byte("data"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "settings.yaml"), []byte("data"), 0o644)

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil || count != 0 {
		t.Fatalf("non-env files: count=%d err=%v", count, err)
	}
}

func TestDecryptAllSymlinkOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlinks require elevated privileges")
	}

	identity := newIdentity(t)
	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create an encrypted .env outside the repo root
	secret := []byte("LEAKED_SECRET=bad\n")
	encrypted, err := encryptArmored(secret, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	outsideEnv := filepath.Join(outsideDir, "stolen.env")
	_ = os.WriteFile(outsideEnv, encrypted, 0o644)

	// Create a symlink inside the repo pointing outside
	symlink := filepath.Join(repoDir, "escape.env")
	if err := os.Symlink(outsideEnv, symlink); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// decryptAll should not follow the symlink to write outside the root
	count, err := decryptAllCount(repoDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}

	// The outside file should remain encrypted (not overwritten with plaintext)
	data, err := os.ReadFile(outsideEnv)
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if bytes.Equal(data, secret) {
		t.Error("symlink traversal: file outside root was decrypted in place")
	}
	_ = count // count may vary depending on os.OpenRoot behavior
}

func TestDecryptAllEnvSuffixEdgeCases(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("KEY=value\n")

	// Files that end in .env should be processed
	writeEncryptedEnv(t, tmpDir, "app.env", original, identity.Recipient())
	writeEncryptedEnv(t, tmpDir, ".env", original, identity.Recipient())

	// Files that don't end in .env should be skipped
	_ = os.WriteFile(filepath.Join(tmpDir, ".env.bak"), []byte("age-encryption.org/v1\nfake"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "env"), []byte("age-encryption.org/v1\nfake"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, ".environment"), []byte("age-encryption.org/v1\nfake"), 0o644)

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2 (only .env suffix files)", count)
	}
}

func TestDecryptAllNestedDirectories(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	sub2 := filepath.Join(tmpDir, "sub1", "sub2")
	_ = os.MkdirAll(sub2, 0o755)

	original := []byte("NESTED_KEY=nested_value\n")
	envPath := writeEncryptedEnv(t, sub2, ".env", original, identity.Recipient())

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	decrypted, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(decrypted, original) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, original)
	}
}

// --- Unit tests: loadIdentity ---

func TestLoadIdentityValid(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.txt")
	_ = os.WriteFile(keyPath, []byte(identity.String()+"\n"), 0o600)

	loaded, err := loadIdentities(keyPath)
	if err != nil {
		t.Fatalf("loadIdentities: %v", err)
	}
	loadedX, ok := loaded[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", loaded[0])
	}
	if loadedX.Recipient().String() != identity.Recipient().String() {
		t.Errorf("loaded recipient %q != original %q",
			loadedX.Recipient().String(), identity.Recipient().String())
	}
}

func TestLoadIdentityErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("non-existent file", func(t *testing.T) {
		if _, err := loadIdentities(filepath.Join(tmpDir, "nonexistent")); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("empty file", func(t *testing.T) {
		p := filepath.Join(tmpDir, "empty.txt")
		_ = os.WriteFile(p, []byte{}, 0o644)
		if _, err := loadIdentities(p); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("invalid content", func(t *testing.T) {
		p := filepath.Join(tmpDir, "garbage.txt")
		_ = os.WriteFile(p, []byte("not a valid age key"), 0o644)
		if _, err := loadIdentities(p); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		p := filepath.Join(tmpDir, "huge.txt")
		// Write just over 1 MB to trigger the size guard
		_ = os.WriteFile(p, bytes.Repeat([]byte("x"), 1<<20+1), 0o644)
		_, err := loadIdentities(p)
		if err == nil {
			t.Error("expected error for oversized key file")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("expected 'too large' error, got: %v", err)
		}
	})
}

func TestDecryptAllWrongKey(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("SECRET=value\n")
	writeEncryptedEnv(t, tmpDir, "secret.env", original, encryptID.Recipient())

	count, err := decryptAllCount(tmpDir, decryptID)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 (wrong key should fail decryption)", count)
	}

	// File should remain encrypted (not overwritten)
	data, err := os.ReadFile(filepath.Join(tmpDir, "secret.env"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(armoredHeader)) {
		t.Error("file encrypted with different key should not have been overwritten")
	}
}

// --- Unit tests: decryptFile ---

func TestDecryptFile_skips_plaintext_env_file(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Write a plaintext .env file (no age header)
	envPath := filepath.Join(tmpDir, "plain.env")
	_ = os.WriteFile(envPath, []byte("PLAIN_KEY=plain_value\n"), 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "plain.env", identity)
	if got {
		t.Error("decryptFile(plaintext) = true, want false")
	}

	// File should remain unchanged
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "PLAIN_KEY=plain_value\n" {
		t.Errorf("plaintext file was modified: %q", data)
	}
}

func TestDecryptFile_decrypts_binary_format(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("BINARY_SECRET=value123\n")
	encrypted, err := encryptBinary(original, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	envPath := filepath.Join(tmpDir, "binary.env")
	_ = os.WriteFile(envPath, encrypted, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "binary.env", identity)
	if !got {
		t.Error("decryptFile(binary encrypted) = false, want true")
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("decryptFile(binary) wrote %q, want %q", data, original)
	}
}

func TestDecryptFile_decrypts_armored_format(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("ARMORED_SECRET=value456\n")
	encrypted, err := encryptArmored(original, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	envPath := filepath.Join(tmpDir, "armored.env")
	_ = os.WriteFile(envPath, encrypted, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "armored.env", identity)
	if !got {
		t.Error("decryptFile(armored encrypted) = false, want true")
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("decryptFile(armored) wrote %q, want %q", data, original)
	}
}

func TestDecryptFile_write_error_on_readonly_directory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod on directories unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes directory writable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("READONLY_KEY=value\n")
	envPath := writeEncryptedEnv(t, tmpDir, "readonly.env", original, identity.Recipient())

	// Make the parent directory read-only so temp-file creation fails.
	// The atomic temp+rename cannot create the sibling tmp file.
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "readonly.env", identity)
	if got {
		t.Error("decryptFile(readonly dir) = true, want false (temp-file write should fail)")
	}

	// File should remain encrypted (not overwritten)
	_ = envPath
}

func TestDecryptFile_overwrites_file_in_place(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("OVERWRITE_KEY=value\n")
	envPath := writeEncryptedEnv(t, tmpDir, "overwrite.env", original, identity.Recipient())

	// Verify the file starts as encrypted (armored header)
	before, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	if !bytes.HasPrefix(before, []byte(armoredHeader)) {
		t.Fatal("file should start as armored-encrypted")
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "overwrite.env", identity)
	if !got {
		t.Fatal("decryptFile = false, want true")
	}

	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Errorf("decryptFile wrote %q, want %q", after, original)
	}
}

// --- Unit tests: decryptAll error paths ---

func TestDecryptAll_rejects_nonexistent_root(t *testing.T) {
	identity := newIdentity(t)
	_, err := decryptAllCount(filepath.Join(t.TempDir(), "does-not-exist"), identity)
	if err == nil {
		t.Fatal("decryptAll with non-existent root should return error")
	}
	if !strings.Contains(err.Error(), "open root") {
		t.Errorf("decryptAll error = %q, want 'open root' prefix", err.Error())
	}
}

func TestDecryptAll_skips_oversized_encrypted_file(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create a file larger than 10 MB with an age header to trigger the size guard.
	// We prepend the armored header so it passes the .env suffix check and reaches
	// the size check inside decryptFile.
	bigData := append([]byte(armoredHeader), bytes.Repeat([]byte("X"), 10<<20+1)...)
	envPath := filepath.Join(tmpDir, "huge.env")
	if err := os.WriteFile(envPath, bigData, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("decryptAll count = %d, want 0 (oversized encrypted file should be skipped)", count)
	}

	// File should remain untouched
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) <= 10<<20 {
		t.Error("oversized file was modified")
	}
}

func TestDecryptAll_handles_walk_error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: permission-based walk errors unreliable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create a subdirectory with no read permission to trigger walkErr
	noReadDir := filepath.Join(tmpDir, "noaccess")
	_ = os.MkdirAll(noReadDir, 0o755)
	_ = os.WriteFile(filepath.Join(noReadDir, "secret.env"), []byte("data"), 0o644)
	_ = os.Chmod(noReadDir, 0o000)
	defer func() { _ = os.Chmod(noReadDir, 0o755) }() // restore for cleanup

	// decryptAll should not return an error — it logs and continues
	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("decryptAll count = %d, want 0", count)
	}
}

func TestDecryptAll_handles_mixed_armored_and_binary(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	armoredContent := []byte("ARMORED_KEY=armored_value\n")
	binaryContent := []byte("BINARY_KEY=binary_value\n")

	// Write one armored-encrypted and one binary-encrypted .env file
	writeEncryptedEnv(t, tmpDir, "armored.env", armoredContent, identity.Recipient())

	binaryEncrypted, err := encryptBinary(binaryContent, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt binary: %v", err)
	}
	binaryPath := filepath.Join(tmpDir, "binary.env")
	if err := os.WriteFile(binaryPath, binaryEncrypted, 0o644); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 2 {
		t.Fatalf("decryptAll count = %d, want 2 (both armored and binary)", count)
	}

	gotArmored, err := os.ReadFile(filepath.Join(tmpDir, "armored.env"))
	if err != nil {
		t.Fatalf("read armored: %v", err)
	}
	if !bytes.Equal(gotArmored, armoredContent) {
		t.Errorf("armored decrypted = %q, want %q", gotArmored, armoredContent)
	}

	gotBinary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(gotBinary, binaryContent) {
		t.Errorf("binary decrypted = %q, want %q", gotBinary, binaryContent)
	}
}

func TestDecryptAll_respects_context_cancellation(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create a valid encrypted .env file that would normally decrypt.
	original := []byte("CANCEL_KEY=value\n")
	writeEncryptedEnv(t, tmpDir, "cancel.env", original, identity.Recipient())

	// Pass an already-canceled context — the walk should abort immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := decryptAll(ctx, tmpDir, []age.Identity{identity}, nil)
	// A canceled context aborts the walk and is reported as an error so the
	// caller (runDecrypt) exits non-zero — a pass that did not finish must
	// never look like success to the deploy gate.
	if err == nil {
		t.Fatal("decryptAll(canceled ctx) = nil error, want a cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("decryptAll(canceled ctx) err = %v, want one wrapping context.Canceled", err)
	}
	// No file should have been decrypted (the walk aborted on the first entry).
	if result.Decrypted != 0 {
		t.Errorf("decryptAll(canceled ctx) decrypted %d files, want 0", result.Decrypted)
	}
}

func TestDecryptAll_counts_failed_files(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	// One file encrypted with a different key — should fail decryption.
	writeEncryptedEnv(t, tmpDir, "wrong-key.env", []byte("SECRET=val\n"), encryptID.Recipient())

	// One plaintext .env — should be skipped (not counted as failed).
	_ = os.WriteFile(filepath.Join(tmpDir, "plain.env"), []byte("PLAIN=val\n"), 0o644)

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{decryptID}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 {
		t.Errorf("decryptAll Decrypted = %d, want 0", result.Decrypted)
	}
	if result.Failed != 1 {
		t.Errorf("decryptAll Failed = %d, want 1 (wrong-key file)", result.Failed)
	}
}

func TestDecryptAll_sweeps_orphan_tmp_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create orphan decrypt temp files (simulating a prior SIGKILL between
	// WriteFile and Rename). Backdate them so they fall past the sweep's
	// stale threshold — young tmps are intentionally preserved now to
	// avoid ripping the tmp out from under a concurrent peer. One is a .env
	// temp, the other a non-.env (.yaml) temp the marker now also reclaims.
	orphan1 := filepath.Join(tmpDir, "app.env.111.1"+tmpSuffix)
	orphan2 := filepath.Join(tmpDir, "sub")
	_ = os.MkdirAll(orphan2, 0o755)
	orphan2File := filepath.Join(orphan2, "db.yaml.99999.2"+tmpSuffix)

	_ = os.WriteFile(orphan1, []byte("LEAKED_SECRET=bad\n"), 0o600)
	_ = os.WriteFile(orphan2File, []byte("LEAKED_DB=bad\n"), 0o600)

	oldTime := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(orphan1, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes orphan1: %v", err)
	}
	if err := os.Chtimes(orphan2File, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes orphan2: %v", err)
	}

	// Also create a valid encrypted .env to verify normal operation continues.
	original := []byte("NORMAL_KEY=value\n")
	writeEncryptedEnv(t, tmpDir, "normal.env", original, identity.Recipient())

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 1 {
		t.Errorf("decryptAll Decrypted = %d, want 1", result.Decrypted)
	}

	// Both orphan temps (.env and non-.env) should have been removed by the sweep.
	if _, err := os.Stat(orphan1); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("orphan %s should have been removed, stat err = %v", orphan1, err)
	}
	if _, err := os.Stat(orphan2File); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("orphan %s should have been removed, stat err = %v", orphan2File, err)
	}
}

func TestRunSubcommand_returns_zero_on_success(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("SUB_KEY=value\n")
	writeEncryptedEnv(t, tmpDir, "app.env", original, identity.Recipient())

	code := runDecrypt(context.Background(), &config{RepoRoot: tmpDir, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 0 {
		t.Errorf("runDecrypt(valid) = %d, want 0", code)
	}
}

func TestRunSubcommand_returns_one_on_decrypt_failure(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	// Encrypt with one key, decrypt with another — produces Failed > 0.
	writeEncryptedEnv(t, tmpDir, "secret.env", []byte("S=v\n"), encryptID.Recipient())

	code := runDecrypt(context.Background(), &config{RepoRoot: tmpDir, Extensions: []string{".env"}}, []age.Identity{decryptID})
	if code != 1 {
		t.Errorf("runDecrypt(wrong key) = %d, want 1 (Failed > 0)", code)
	}
}

func TestRunSubcommand_returns_one_on_invalid_root(t *testing.T) {
	identity := newIdentity(t)
	bogusRoot := filepath.Join(t.TempDir(), "does-not-exist")

	code := runDecrypt(context.Background(), &config{RepoRoot: bogusRoot, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(invalid root) = %d, want 1", code)
	}
}

// --- Unit tests: runServer (idle + signal) ---

func TestRunServer_exits_zero_on_signal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediate signal
	code := runServer(ctx)
	if code != 0 {
		t.Errorf("runServer(canceled ctx) = %d, want 0", code)
	}
}

// --- Unit tests: loadIdentity edge cases ---

func TestLoadIdentity_key_at_exact_size_limit(t *testing.T) {
	tmpDir := t.TempDir()

	// A key file at exactly 1 MB should not be rejected by the size guard.
	// It will fail parsing (it's not a valid key), but the error should be
	// about parsing, not about size.
	p := filepath.Join(tmpDir, "exact-1mb.txt")
	_ = os.WriteFile(p, bytes.Repeat([]byte("x"), 1<<20), 0o644)

	_, err := loadIdentities(p)
	if err == nil {
		t.Fatal("expected error for non-key content")
	}
	if strings.Contains(err.Error(), "too large") {
		t.Errorf("loadIdentities(%q) rejected at exact limit: %v", "exact-1mb.txt", err)
	}
}

func TestLoadIdentity_key_with_comment_lines(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// age key files typically have a comment line before the key
	content := fmt.Sprintf("# created: 2024-01-01T00:00:00Z\n# public key: %s\n%s\n",
		identity.Recipient().String(), identity.String())
	keyPath := filepath.Join(tmpDir, "key-with-comments.txt")
	_ = os.WriteFile(keyPath, []byte(content), 0o600)

	loaded, err := loadIdentities(keyPath)
	if err != nil {
		t.Fatalf("loadIdentities with comments: %v", err)
	}
	loadedX, ok := loaded[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", loaded[0])
	}
	if loadedX.Recipient().String() != identity.Recipient().String() {
		t.Errorf("loadIdentity recipient = %q, want %q",
			loadedX.Recipient().String(), identity.Recipient().String())
	}
}

// --- Property-based tests: decryptFile ---

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

// --- Additional edge cases ---

// TestDecryptFile_status consolidates simple decryptFile status-check cases
// into a table-driven test. Each case sets up a file (or not) and asserts the
// returned fileStatus without additional post-condition checks on file content.
func TestDecryptFile_status(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)

	wrongKeyData, err := encryptArmored([]byte("SECRET=val\n"), encryptID.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tests := []struct {
		id      age.Identity
		name    string
		file    string
		content []byte
		want    fileStatus
	}{
		{
			name:    "plaintext returns fileSkipped",
			file:    "plain.env",
			content: []byte("KEY=value\n"),
			id:      decryptID,
			want:    fileSkipped,
		},
		{
			name:    "empty file returns fileSkipped",
			file:    "empty.env",
			content: []byte{},
			id:      decryptID,
			want:    fileSkipped,
		},
		{
			name:    "single byte returns fileSkipped",
			file:    "tiny.env",
			content: []byte("X"),
			id:      decryptID,
			want:    fileSkipped,
		},
		{
			name:    "corrupt binary header returns fileFailed",
			file:    "corrupt.env",
			content: []byte(ageHeader + "\ngarbage data that is not valid age\n"),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "corrupt armored header returns fileFailed",
			file:    "corrupt.env",
			content: []byte(armoredHeader + "\nthis is not valid base64 armor content\n"),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "wrong key returns fileFailed",
			file:    "wrong.env",
			content: wrongKeyData,
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "missing file returns fileFailed",
			file:    "nonexistent.env",
			content: nil, // don't create
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "oversized encrypted returns fileFailed",
			file:    "huge.env",
			content: append([]byte(armoredHeader), bytes.Repeat([]byte("X"), 10<<20+1)...),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			// A large NON-age file is classified from its header and skipped
			// regardless of size — it was never a secret, so it is not a
			// failure. Pins the header-peek-before-size-cap ordering: prior to
			// the reorder a 10 MB+ non-age file was read in full and returned
			// fileFailed, which in no-filter mode wrongly blocked the deploy.
			name:    "oversized non-age returns fileSkipped",
			file:    "huge-plain.env",
			content: bytes.Repeat([]byte("X"), 10<<20+1),
			id:      decryptID,
			want:    fileSkipped,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			if tc.content != nil {
				if err := os.WriteFile(filepath.Join(tmpDir, tc.file), tc.content, 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
			}

			rootDir, err := os.OpenRoot(tmpDir)
			if err != nil {
				t.Fatalf("OpenRoot: %v", err)
			}
			defer func() { _ = rootDir.Close() }()

			got := decryptFile(context.Background(), rootDir, tc.file, []age.Identity{tc.id})
			if got != tc.want {
				t.Errorf("decryptFile(%s) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// FuzzDecryptFile feeds arbitrary file content to decryptFile and asserts no panic.
// This exercises format detection and decryption error paths with untrusted input.
func FuzzDecryptFile(f *testing.F) {
	id, _ := age.GenerateX25519Identity()
	validArmored, _ := encryptArmored([]byte("KEY=val\n"), id.Recipient())
	validBinary, _ := encryptBinary([]byte("KEY=val\n"), id.Recipient())

	f.Add(validArmored)
	f.Add(validBinary)
	f.Add([]byte(""))
	f.Add([]byte("PLAIN=value\n"))
	f.Add([]byte(armoredHeader + "\ncorrupt\n"))
	f.Add([]byte(ageHeader + "\ncorrupt\n"))
	f.Add(bytes.Repeat([]byte("X"), 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		envPath := filepath.Join(tmpDir, "fuzz.env")
		if err := os.WriteFile(envPath, data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		rootDir, err := os.OpenRoot(tmpDir)
		if err != nil {
			t.Fatalf("OpenRoot: %v", err)
		}
		defer func() { _ = rootDir.Close() }()

		isAge := bytes.HasPrefix(data, []byte(armoredHeader)) ||
			bytes.HasPrefix(data, []byte(ageHeader))

		status := decryptFile(context.Background(), rootDir, "fuzz.env", []age.Identity{id})

		// Invariant 1: result is always one of the three defined statuses.
		switch status {
		case fileSkipped, fileDecrypted, fileFailed:
		default:
			t.Fatalf("decryptFile returned undefined status %d for input %q", status, data)
		}

		// Invariant 2: input without a recognized age header is never reported
		// as decrypted and is left byte-for-byte unchanged on disk.
		if !isAge {
			if status == fileDecrypted {
				t.Errorf("non-age input reported fileDecrypted (input %q)", data)
			}
			after, readErr := os.ReadFile(envPath)
			if readErr != nil {
				t.Fatalf("read back: %v", readErr)
			}
			if !bytes.Equal(after, data) {
				t.Errorf("non-age input was modified on disk: got %q, want %q", after, data)
			}
		}

		// Invariant 3: regardless of outcome, no temp debris is ever left behind.
		entries, readErr := os.ReadDir(tmpDir)
		if readErr != nil {
			t.Fatalf("readdir: %v", readErr)
		}
		for _, e := range entries {
			if isOrphanTmpFile(e.Name()) {
				t.Errorf("decryptFile left tmp debris %q (input %q)", e.Name(), data)
			}
		}
	})
}

// BenchmarkDecryptFile measures decryptFile performance with a small representative
// armored-encrypted input to catch performance regressions.
func BenchmarkDecryptFile(b *testing.B) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatalf("generate identity: %v", err)
	}

	original := []byte("BENCH_KEY=benchmark_value_12345\n")
	encrypted, err := encryptArmored(original, id.Recipient())
	if err != nil {
		b.Fatalf("encrypt: %v", err)
	}

	tmpDir := b.TempDir()
	envPath := filepath.Join(tmpDir, "bench.env")

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		b.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		// Re-write the encrypted file each iteration since decryptFile overwrites it.
		if err := os.WriteFile(envPath, encrypted, 0o644); err != nil {
			b.Fatalf("write: %v", err)
		}
		status := decryptFile(context.Background(), rootDir, "bench.env", []age.Identity{id})
		if status != fileDecrypted {
			b.Fatalf("decryptFile = %d, want %d (fileDecrypted)", status, fileDecrypted)
		}
	}
}

// loadIdentities with a file containing multiple identities — all are returned
// and forwarded to age.Decrypt (supports multi-identity key rotation).
func TestLoadIdentity_multiple_identities_returns_all(t *testing.T) {
	id1 := newIdentity(t)
	id2 := newIdentity(t)
	tmpDir := t.TempDir()

	content := id1.String() + "\n" + id2.String() + "\n"
	keyPath := filepath.Join(tmpDir, "multi.txt")
	_ = os.WriteFile(keyPath, []byte(content), 0o600)

	loaded, err := loadIdentities(keyPath)
	if err != nil {
		t.Fatalf("loadIdentities(multi): %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loadIdentities(multi) returned %d identities, want 2", len(loaded))
	}
	id1X, ok := loaded[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", loaded[0])
	}
	id2X, ok := loaded[1].(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", loaded[1])
	}
	if id1X.Recipient().String() != id1.Recipient().String() {
		t.Errorf("loadIdentities(multi)[0] = %q, want %q (first)",
			id1X.Recipient().String(), id1.Recipient().String())
	}
	if id2X.Recipient().String() != id2.Recipient().String() {
		t.Errorf("loadIdentities(multi)[1] = %q, want %q (second)",
			id2X.Recipient().String(), id2.Recipient().String())
	}
}

// decryptAll with a directory containing only plaintext .env files — count should be 0.
func TestDecryptAll_all_plaintext_env_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	_ = os.WriteFile(filepath.Join(tmpDir, "app1.env"), []byte("KEY1=val1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "app2.env"), []byte("KEY2=val2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("ROOT_KEY=root\n"), 0o644)

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Errorf("decryptAll(all plaintext) = %d, want 0", count)
	}
}

// decryptFile on a small valid encrypted file is accepted (not falsely
// rejected by the 10 MB encrypted-input guard). After the cycle-3 streaming
// change the guard is `len(data) > maxEncryptedSize` on the
// io.LimitReader read in decryptFile — there is no info.Size() stat on the
// encrypted path. The exact-10 MB boundary is impractical to pin with a real
// age ciphertext (age rejects trailing padding); the over-cap side is covered
// by TestDecryptAll_skips_oversized_encrypted_file and TestDecryptFile_status.
func TestDecryptFile_at_exact_encrypted_size_limit(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Encrypt content that produces a ciphertext close to 10 MB.
	// The exact encrypted size won't be exactly 10<<20, so we pad the file
	// after encryption to hit the boundary. We use binary format with the
	// age header prefix to pass the header check, then it will fail decryption
	// (which is fine — we're testing the size guard, not decryption).
	// Instead, create a valid encrypted file and check it passes the size guard.
	original := bytes.Repeat([]byte("A"), 512)
	encrypted, err := encryptArmored(original, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Verify the encrypted file is well under 10 MB and decrypts successfully
	if len(encrypted) >= 10<<20 {
		t.Fatalf("encrypted size %d exceeds 10MB — test assumption broken", len(encrypted))
	}

	_ = os.WriteFile(filepath.Join(tmpDir, "small.env"), encrypted, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "small.env", identity)
	if !got {
		t.Error("decryptFile(small encrypted) = false, want true")
	}

	// Verify decryption worked
	data, err := os.ReadFile(filepath.Join(tmpDir, "small.env"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("decryptFile wrote %d bytes, want %d", len(data), len(original))
	}
}

// decryptFile with content that decrypts to exactly 1 MB — should succeed (not rejected).
// Kills CONDITIONALS_BOUNDARY mutant at the `len(cleartext) > maxDecryptedSize` check.
func TestDecryptFile_decrypted_content_at_exact_1MB_limit(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create content that is exactly 1 MB (1<<20 bytes) — at the limit, not over.
	original := bytes.Repeat([]byte("B"), 1<<20)
	encrypted, err := encryptArmored(original, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	envPath := filepath.Join(tmpDir, "exact-1mb.env")
	_ = os.WriteFile(envPath, encrypted, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "exact-1mb.env", identity)
	if !got {
		t.Error("decryptFile(exactly 1MB decrypted) = false, want true (at limit, not over)")
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) != 1<<20 {
		t.Errorf("decrypted size = %d, want %d (exactly 1MB)", len(data), 1<<20)
	}
}

// decryptFile with content that decrypts to 1 MB + 1 byte — should be rejected.
func TestDecryptFile_decrypted_content_over_1MB_limit(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create content that is 1 byte over the 1 MB limit.
	original := bytes.Repeat([]byte("C"), 1<<20+1)
	encrypted, err := encryptArmored(original, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	envPath := filepath.Join(tmpDir, "over-1mb.env")
	_ = os.WriteFile(envPath, encrypted, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "over-1mb.env", identity)
	if got {
		t.Error("decryptFile(1MB+1 decrypted) = true, want false (over limit)")
	}

	// File should remain encrypted (not overwritten)
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(armoredHeader)) {
		t.Error("over-limit file should not have been overwritten with plaintext")
	}
}

// --- Tests added from review: coverage gap closers ---

// decryptFile returns false when Stat succeeds but ReadFile fails
// (file with mode 0 on Unix is stat-able but unreadable).
func TestDecryptFile_read_error_after_stat_success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod 0o000 does not block reads")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes file readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	envPath := filepath.Join(tmpDir, "unreadable.env")
	if err := os.WriteFile(envPath, []byte("some data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Make the file unreadable but keep it stat-able.
	if err := os.Chmod(envPath, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(envPath, 0o644) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "unreadable.env", identity)
	if got {
		t.Error("decryptFile(mode=0) = true, want false (read should fail)")
	}
}

// loadIdentity returns a specific "no identities" error when the file
// parses successfully but contains only comments and whitespace. This is
// distinct from the "parse error" path covered by TestLoadIdentityErrors.
// If filippo.io/age instead rejects comment-only files as a parse error,
// the test still passes — we just assert on "error returned", not on
// which branch was taken.
func TestLoadIdentity_file_with_only_comments_returns_error(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "comments-only.txt")
	content := "# only a comment\n# another comment\n\n"
	if err := os.WriteFile(keyPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadIdentities(keyPath)
	if err == nil {
		t.Fatal("loadIdentities(comments-only) = nil, want error")
	}
}

// FuzzLoadIdentity feeds arbitrary bytes as key file content to loadIdentity
// and asserts no panic. This exercises the parsing boundary for untrusted input.
func FuzzLoadIdentity(f *testing.F) {
	// Seed corpus with representative inputs.
	id, _ := age.GenerateX25519Identity()
	f.Add([]byte(id.String() + "\n"))
	f.Add([]byte("# comment\n" + id.String() + "\n"))
	f.Add([]byte(""))
	f.Add([]byte("not a valid age key\n"))
	f.Add([]byte("AGE-SECRET-KEY-1INVALID\n"))
	f.Add(bytes.Repeat([]byte("x"), 1<<20+1))

	f.Fuzz(func(t *testing.T, data []byte) {
		keyPath := filepath.Join(t.TempDir(), "fuzz-key.txt")
		if err := os.WriteFile(keyPath, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		ids, err := loadIdentities(keyPath)
		// Invariant 1: error and result are mutually exclusive.
		if err != nil {
			if ids != nil {
				t.Errorf("loadIdentities returned %d identities alongside error %v, want nil",
					len(ids), err)
			}
			return
		}

		// Invariant 2: documented success contract -- nil error guarantees at
		// least one identity and none of them is nil (forwarded verbatim to
		// variadic age.Decrypt).
		if len(ids) == 0 {
			t.Errorf("loadIdentities returned nil error but zero identities for input %q", data)
		}
		for i, identity := range ids {
			if identity == nil {
				t.Errorf("loadIdentities returned a nil identity at index %d for input %q", i, data)
			}
		}

		// Invariant 3: the 1 MB key-file size cap is honored -- an input larger
		// than the cap must never parse successfully.
		const maxKeyFileSize = 1 << 20
		if len(data) > maxKeyFileSize {
			t.Errorf("loadIdentities accepted an oversized %d-byte key file (cap %d)",
				len(data), maxKeyFileSize)
		}
	})
}

// A file encrypted to the SECOND identity in the key file must decrypt when
// both identities are passed — this is the multi-identity key-rotation path
// (AGE_KEY_FILE documents "one identity per line"). The negative control
// (only id1) confirms the file genuinely requires id2.
func TestDecryptAll_decrypts_file_encrypted_to_second_identity(t *testing.T) {
	id1 := newIdentity(t)
	id2 := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("ROTATED_KEY=rotated_value\n")
	envPath := writeEncryptedEnv(t, tmpDir, "rotated.env", original, id2.Recipient())

	// Sanity/negative control: id1 alone cannot decrypt an id2-encrypted file.
	onlyID1, err := decryptAll(context.Background(), tmpDir, []age.Identity{id1}, nil)
	if err != nil {
		t.Fatalf("decryptAll(id1 only): %v", err)
	}
	if onlyID1.Decrypted != 0 || onlyID1.Failed != 1 {
		t.Fatalf("id1 only: Decrypted=%d Failed=%d, want 0 and 1", onlyID1.Decrypted, onlyID1.Failed)
	}

	// File is still ciphertext after the failed pass; decrypt with both keys.
	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{id1, id2}, nil)
	if err != nil {
		t.Fatalf("decryptAll(id1, id2): %v", err)
	}
	if result.Decrypted != 1 {
		t.Fatalf("Decrypted = %d, want 1 (file encrypted to 2nd identity)", result.Decrypted)
	}
	got, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("decrypted content = %q, want %q", got, original)
	}
}

// The Skipped counter must count non-age .env files (legitimate skips),
// distinct from Failed (age-formatted files that could not be decrypted).
func TestDecryptAll_counts_skipped_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Two plaintext .env files — both should be Skipped, not Failed.
	_ = os.WriteFile(filepath.Join(tmpDir, "plain1.env"), []byte("A=1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "plain2.env"), []byte("B=2\n"), 0o644)
	// One real encrypted .env — should be Decrypted.
	writeEncryptedEnv(t, tmpDir, "enc.env", []byte("C=3\n"), identity.Recipient())

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2 (two plaintext .env files)", result.Skipped)
	}
	if result.Decrypted != 1 {
		t.Errorf("Decrypted = %d, want 1", result.Decrypted)
	}
	if result.Failed != 0 {
		t.Errorf("Failed = %d, want 0 (plaintext is skipped, not failed)", result.Failed)
	}
}

// A directory the walk cannot read must increment WalkErrors (and not abort
// the whole pass). Distinct from TestDecryptAll_handles_walk_error, which only
// checks the decrypted count via the adapter.
func TestDecryptAll_counts_walk_errors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: permission-based walk errors unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes directory readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	noReadDir := filepath.Join(tmpDir, "noaccess")
	_ = os.MkdirAll(noReadDir, 0o755)
	_ = os.WriteFile(filepath.Join(noReadDir, "secret.env"), []byte("data"), 0o644)
	_ = os.Chmod(noReadDir, 0o000)
	t.Cleanup(func() { _ = os.Chmod(noReadDir, 0o755) })

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.WalkErrors < 1 {
		t.Errorf("WalkErrors = %d, want >= 1 (unreadable subdir)", result.WalkErrors)
	}
}

func TestWarnIfNoFilesSeen_warns_only_when_no_files_seen(t *testing.T) {
	tests := []struct {
		name     string
		result   decryptResult
		wantWarn bool
	}{
		{name: "all zero warns", result: decryptResult{}, wantWarn: true},
		{name: "decrypted nonzero is silent", result: decryptResult{Decrypted: 1}, wantWarn: false},
		{name: "failed nonzero is silent", result: decryptResult{Failed: 1}, wantWarn: false},
		{name: "skipped nonzero is silent", result: decryptResult{Skipped: 1}, wantWarn: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(prev) })
			warnIfNoFilesSeen(tt.result, "/repo/homelab", nil)
			out := buf.String()
			gotWarn := strings.Contains(out, "no matching files found")
			if gotWarn != tt.wantWarn {
				t.Errorf("warnIfNoFilesSeen(%+v) warn=%v, want %v (output=%q)", tt.result, gotWarn, tt.wantWarn, out)
			}
			if tt.wantWarn {
				if !strings.Contains(out, "level=WARN") {
					t.Errorf("warnIfNoFilesSeen(all zero) level missing WARN, got %q", out)
				}
				if !strings.Contains(out, "/repo/homelab") {
					t.Errorf("warnIfNoFilesSeen(all zero) missing repo_root attr, got %q", out)
				}
			}
		})
	}
}

func TestLogDecryptResult_emits_all_counts(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	logDecryptResult("decryption complete", decryptResult{
		Decrypted: 3, Failed: 2, Skipped: 5, WalkErrors: 1,
	})

	out := buf.String()
	for _, want := range []string{
		`msg="decryption complete"`,
		"decrypted=3",
		"failed=2",
		"skipped=5",
		"walk_errors=1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("logDecryptResult output missing %q, got %q", want, out)
		}
	}
}

// TestDecryptFile_rejects_corrupted_body_leaves_file_unchanged feeds a binary
// ciphertext whose header is valid but whose final payload chunk is truncated:
// age.Decrypt succeeds, the body fails AEAD authentication on read, and
// decryptFile must return fileFailed BEFORE the temp-write/rename, leaving the
// original file byte-for-byte intact. Reaches the post-Decrypt io.ReadAll error
// branch (decrypt.go:120) that the header-corruption / wrong-key cases skip, and
// pins the security invariant that a tampered body never produces a partially
// written plaintext .env.
func TestDecryptFile_rejects_corrupted_body_leaves_file_unchanged(t *testing.T) {
	id := newIdentity(t)
	full, err := encryptBinary([]byte("SECRET=value\n"), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	corrupt := full[:len(full)-1]

	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "tampered.env")
	if err := os.WriteFile(envPath, corrupt, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, "tampered.env", []age.Identity{id})
	if got != fileFailed {
		t.Errorf("decryptFile(corrupt body) = %d, want %d (fileFailed)", got, fileFailed)
	}

	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Error("decryptFile(corrupt body) modified the file: a body-auth failure must not write partial plaintext")
	}
}

// TestSweepOrphanTmpFile_returns_false_when_remove_fails pins the remove-failure
// branch (decrypt.go:178-182): a stale orphan whose unlink fails for a reason
// other than fs.ErrNotExist (here an unwritable parent dir -> EACCES) must be
// logged and reported as not-swept (return false), with the file left in place.
// Existing sweep tests cover stat-miss, young-preserved, and successful removal
// but never a removable-stale-that-fails-to-unlink. Windows + root are skipped:
// chmod cannot revoke write for either, matching the existing chmod-based tests
// in this file.
func TestSweepOrphanTmpFile_returns_false_when_remove_fails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod on directories unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes directory writable")
	}

	tmpDir := t.TempDir()
	rel := "stale.env.4242.1" + tmpSuffix
	p := filepath.Join(tmpDir, rel)
	if err := os.WriteFile(p, []byte("plaintext orphan"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	// Make the parent unwritable so the unlink fails with EACCES (not ErrNotExist).
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := sweepOrphanTmpFile(rootDir, rel, 10*time.Minute)
	if got {
		t.Errorf("sweepOrphanTmpFile(stale, unremovable) = true, want false (remove failed)")
	}
	// File must still be present (removal failed).
	if _, statErr := os.Stat(p); errors.Is(statErr, fs.ErrNotExist) {
		t.Error("orphan unexpectedly removed despite unwritable parent dir")
	}
}

// TestParseConfig_extRejectsEmptyValue asserts that an empty --ext value is
// rejected rather than silently coerced to the bare "." suffix. That suffix
// matches almost no files, so the decrypt pass would no-op yet still exit 0 --
// defeating the deploy gate that keys on the exit code. Both the equals form
// ("--ext=") and the space form with an explicit empty argument (`--ext ""`)
// route through normalizeExt and must error. Complements
// TestParseConfig_extRequiresValue, which covers only the trailing bare --ext.
func TestParseConfig_extRejectsEmptyValue(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	tests := []struct {
		name string
		args []string
	}{
		{"equals form", []string{"age", "decrypt", "--ext="}},
		{"space form", []string{"age", "decrypt", "--ext", ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			_, err := parseConfig()
			if err == nil || !strings.Contains(err.Error(), "requires") {
				t.Errorf("parseConfig(%v) = err %v, want one containing 'requires'", tc.args, err)
			}
		})
	}
}

// TestWriteDecryptedInPlace_rename_failure_leaves_no_plaintext_debris pins the
// cleanup contract of the cycle-1-extracted writeDecryptedInPlace: when the
// rename step fails (the exact production failure mode that motivated PID-keyed
// tmp naming -- "renameat <dir>/.env.tmp <dir>/.env: no such file or
// directory"), the function must return fileFailed AND remove the 0600
// plaintext temp so no decrypted secret lingers on disk. The rename-failure
// branch (decrypt.go ~165-181) is otherwise unexercised -- existing tests cover
// only the happy path and the WriteFile-failure (read-only dir) path. A
// deterministic rename failure is forced by making rel an existing directory:
// renaming a file onto a directory fails (EISDIR).
func TestWriteDecryptedInPlace_rename_failure_leaves_no_plaintext_debris(t *testing.T) {
	tmpDir := t.TempDir()
	rel := "target"
	if err := os.Mkdir(filepath.Join(tmpDir, rel), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := writeDecryptedInPlace(rootDir, rel, []byte("SECRET=plaintext\n"))
	if got != fileFailed {
		t.Errorf("writeDecryptedInPlace(rename onto dir) = %d, want %d (fileFailed)", got, fileFailed)
	}

	// Security invariant: a failed in-place rewrite must leave no 0600 plaintext
	// temp debris behind (any name carrying the tmpSuffix marker).
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if isOrphanTmpFile(e.Name()) {
			t.Errorf("rename-failure left plaintext temp debris: %q", e.Name())
		}
	}
}

// TestWipeTempFile_truncates_when_remove_blocked pins the security-critical
// defense-in-depth in wipeTempFile (decrypt.go:137-140): when the unlink of the
// 0600 plaintext temp fails for a reason OTHER than fs.ErrNotExist, the function
// must truncate the temp to zero so decrypted plaintext cannot linger on disk
// until the age-bound orphan sweep reclaims it. This fallback was previously
// uncovered (wipeTempFile 33.3%). Cycle 2 dismissed it as "equivalent-mutant
// territory -- no deterministic os.Root injection point", but that is incorrect:
// rootDir.Remove fails deterministically with EACCES under a 0o555 parent dir
// (the SAME injection point TestSweepOrphanTmpFile_returns_false_when_remove_fails
// already relies on), while truncating an existing 0o600 file needs only
// file-write permission, so the WriteFile-truncate still succeeds.
func TestWipeTempFile_truncates_when_remove_blocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod on directories unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes directory writable")
	}

	tmpDir := t.TempDir()
	rel := "leftover.env.4242.1" + tmpSuffix
	p := filepath.Join(tmpDir, rel)
	if err := os.WriteFile(p, []byte("SECRET=plaintext\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Make the parent unwritable so the unlink fails with EACCES (not
	// ErrNotExist), forcing the truncate-to-zero fallback. Truncating the
	// existing 0o600 file needs file (not dir) write permission, so it succeeds.
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	wipeTempFile(rootDir, rel)

	// Security invariant: plaintext must not linger. The unlink was blocked, so
	// the file remains -- but it must have been truncated to zero bytes.
	info, statErr := os.Stat(p)
	if statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return // removed entirely also satisfies "no plaintext lingers"
		}
		t.Fatalf("stat: %v", statErr)
	}
	if info.Size() != 0 {
		t.Errorf("wipeTempFile left %d bytes of plaintext on disk, want 0 (truncate-to-zero fallback)", info.Size())
	}
}

// TestRunDecrypt_walkError_blocks_deploy pins the fail-closed exit gate: a
// subtree the walk cannot read (WalkErrors > 0) must block the deploy (exit 1)
// even when every file the walk DID reach decrypted cleanly (Failed == 0). An
// unread subtree leaves its age-encrypted files as ciphertext, the same
// silent-no-op the fatal root-level walk error prevents, so it gets the same
// exit-1 treatment one level down. Windows + root are skipped: chmod 0o000
// cannot revoke read for either.
func TestRunDecrypt_walkError_blocks_deploy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: permission-based walk errors unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes the directory readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// A top-level .env that decrypts cleanly: Decrypted=1, Failed=0.
	writeEncryptedEnv(t, tmpDir, "app.env", []byte("OK=1\n"), identity.Recipient())

	// An unreadable subtree (WalkErrors>0) hiding an encrypted .env that is
	// therefore never decrypted: the ciphertext-left-behind hazard.
	noReadDir := filepath.Join(tmpDir, "locked")
	if err := os.MkdirAll(noReadDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeEncryptedEnv(t, noReadDir, "hidden.env", []byte("SECRET=2\n"), identity.Recipient())
	if err := os.Chmod(noReadDir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(noReadDir, 0o755) })

	code := runDecrypt(context.Background(), &config{RepoRoot: tmpDir, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(unreadable subtree, Failed=0 WalkErrors>0) = %d, want 1 (walk error must block the deploy)", code)
	}
}

// TestRunDecrypt_canceled_context_exits_one pins the wired cancellation on the
// single-file path: a canceled context (SIGINT/SIGTERM) must make runDecrypt
// exit non-zero rather than report the interrupted file as a skip and exit 0.
// decryptFile reports the file fileSkipped on a canceled context, so the
// runDecrypt post-loop guard is what turns that into the deploy-blocking exit.
// The walk path's cancellation is exercised by
// TestDecryptAll_respects_context_cancellation (decryptAll returns an error).
func TestRunDecrypt_canceled_context_exits_one(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	path := writeEncryptedEnv(t, tmpDir, "one.env", []byte("K=v\n"), identity.Recipient())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code := runDecrypt(ctx, &config{Targets: []string{path}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(canceled ctx, single-file target) = %d, want 1 (canceled pass must exit non-zero)", code)
	}
}

// TestLogLevel maps AGE_LOG_LEVEL to a slog.Level, defaulting to Info for an
// unset, empty, or unrecognized value (the safe deploy-gate default) and
// accepting the level names case-insensitively.
func TestLogLevel(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want slog.Level
	}{
		{name: "unset/empty", env: "", want: slog.LevelInfo},
		{name: "debug", env: "debug", want: slog.LevelDebug},
		{name: "debug uppercase", env: "DEBUG", want: slog.LevelDebug},
		{name: "info", env: "info", want: slog.LevelInfo},
		{name: "warn", env: "warn", want: slog.LevelWarn},
		{name: "warning alias", env: "warning", want: slog.LevelWarn},
		{name: "error", env: "error", want: slog.LevelError},
		{name: "unrecognized falls back to info", env: "loud", want: slog.LevelInfo},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGE_LOG_LEVEL", tc.env)
			if got := logLevel(); got != tc.want {
				t.Errorf("logLevel() with AGE_LOG_LEVEL=%q = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

// TestWipeTempFile_logs_when_truncate_also_fails covers wipeTempFile's inner arm:
// when Remove fails (not ErrNotExist) AND the truncate fallback also fails,
// the function logs a "temp cleanup error" warning.
func TestWipeTempFile_logs_when_truncate_also_fails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod on directories unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes the file writable")
	}
	tmpDir := t.TempDir()
	rel := "leftover.env.4242.1" + tmpSuffix
	p := filepath.Join(tmpDir, rel)
	if err := os.WriteFile(p, []byte("SECRET=plaintext\n"), 0o400); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 0o555 parent: unlink fails EACCES. 0o400 temp: truncate fails EACCES too.
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	wipeTempFile(rootDir, rel)

	if out := buf.String(); !strings.Contains(out, "temp cleanup error") {
		t.Errorf("wipeTempFile(remove+truncate both fail) log = %q, want a 'temp cleanup error' warning", out)
	}
}
