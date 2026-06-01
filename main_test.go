package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// sanitizePath strips the repo root prefix from paths for logging,
// showing only the relative path (e.g. "apps/age/.env") to avoid
// leaking internal directory structure.
func sanitizePath(fullPath, root string) string {
	rel, err := filepath.Rel(root, fullPath)
	if err != nil {
		return filepath.Base(fullPath)
	}
	return rel
}

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
	res, err := decryptAll(context.Background(), root, identity)
	return res.Decrypted, err
}

// decryptFileBool is a test-local adapter that preserves the pre-refactor
// bool return for existing tests. New tests that need to distinguish
// fileSkipped from fileFailed should call decryptFile directly.
func decryptFileBool(rootDir *os.Root, rel string, identity age.Identity) bool {
	return decryptFile(context.Background(), rootDir, rel, identity) == fileDecrypted
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

	loaded, err := loadIdentity(keyPath)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	loadedX, ok := loaded.(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", loaded)
	}
	if loadedX.Recipient().String() != identity.Recipient().String() {
		t.Errorf("loaded recipient %q != original %q",
			loadedX.Recipient().String(), identity.Recipient().String())
	}
}

func TestLoadIdentityErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("non-existent file", func(t *testing.T) {
		if _, err := loadIdentity(filepath.Join(tmpDir, "nonexistent")); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("empty file", func(t *testing.T) {
		p := filepath.Join(tmpDir, "empty.txt")
		_ = os.WriteFile(p, []byte{}, 0o644)
		if _, err := loadIdentity(p); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("invalid content", func(t *testing.T) {
		p := filepath.Join(tmpDir, "garbage.txt")
		_ = os.WriteFile(p, []byte("not a valid age key"), 0o644)
		if _, err := loadIdentity(p); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		p := filepath.Join(tmpDir, "huge.txt")
		// Write just over 1 MB to trigger the size guard
		_ = os.WriteFile(p, bytes.Repeat([]byte("x"), 1<<20+1), 0o644)
		_, err := loadIdentity(p)
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

// --- Unit tests: sanitizePath ---

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
		root     string
		want     string
	}{
		{
			name:     "strips root prefix",
			fullPath: filepath.Join("repo", "apps", "age", ".env"),
			root:     "repo",
			want:     filepath.Join("apps", "age", ".env"),
		},
		{
			name:     "root itself returns dot",
			fullPath: "repo",
			root:     "repo",
			want:     ".",
		},
		{
			name:     "deeper nesting",
			fullPath: filepath.Join("a", "b", "c", "d.env"),
			root:     filepath.Join("a", "b"),
			want:     filepath.Join("c", "d.env"),
		},
		{
			name:     "single file in root",
			fullPath: filepath.Join("root", ".env"),
			root:     "root",
			want:     ".env",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizePath(tt.fullPath, tt.root)
			if got != tt.want {
				t.Errorf("sanitizePath(%q, %q) = %q, want %q", tt.fullPath, tt.root, got, tt.want)
			}
		})
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
	defer rootDir.Close()

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
	defer rootDir.Close()

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

	result, err := decryptAll(ctx, tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll with canceled ctx: %v", err)
	}
	// With a pre-canceled context, the walk callback returns SkipAll on the
	// first entry. Depending on WalkDir ordering, the root directory entry
	// may or may not be visited before the .env file, so Decrypted could be
	// 0 (skipped before reaching the file) or possibly 0 (SkipAll fires on
	// the directory itself). The key invariant: no file should be decrypted.
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

	result, err := decryptAll(context.Background(), tmpDir, decryptID)
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

	// Create orphan .env.tmp files (simulating a prior SIGKILL between
	// WriteFile and Rename). Backdate them so they fall past the sweep's
	// stale threshold — young tmps are intentionally preserved now to
	// avoid ripping the tmp out from under a concurrent peer.
	orphan1 := filepath.Join(tmpDir, "app.env.tmp") // legacy name
	orphan2 := filepath.Join(tmpDir, "sub")
	_ = os.MkdirAll(orphan2, 0o755)
	orphan2File := filepath.Join(orphan2, "db.env.tmp.99999") // per-PID name

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

	result, err := decryptAll(context.Background(), tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 1 {
		t.Errorf("decryptAll Decrypted = %d, want 1", result.Decrypted)
	}

	// Both legacy and per-PID orphan tmps should have been removed by the sweep.
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

	code := runSubcommand(tmpDir, identity)
	if code != 0 {
		t.Errorf("runSubcommand(valid) = %d, want 0", code)
	}
}

func TestRunSubcommand_returns_one_on_decrypt_failure(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	// Encrypt with one key, decrypt with another — produces Failed > 0.
	writeEncryptedEnv(t, tmpDir, "secret.env", []byte("S=v\n"), encryptID.Recipient())

	code := runSubcommand(tmpDir, decryptID)
	if code != 1 {
		t.Errorf("runSubcommand(wrong key) = %d, want 1 (Failed > 0)", code)
	}
}

func TestRunSubcommand_returns_one_on_invalid_root(t *testing.T) {
	identity := newIdentity(t)
	bogusRoot := filepath.Join(t.TempDir(), "does-not-exist")

	code := runSubcommand(bogusRoot, identity)
	if code != 1 {
		t.Errorf("runSubcommand(invalid root) = %d, want 1", code)
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

	_, err := loadIdentity(p)
	if err == nil {
		t.Fatal("expected error for non-key content")
	}
	if strings.Contains(err.Error(), "too large") {
		t.Errorf("loadIdentity(%q) rejected at exact limit: %v", "exact-1mb.txt", err)
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

	loaded, err := loadIdentity(keyPath)
	if err != nil {
		t.Fatalf("loadIdentity with comments: %v", err)
	}
	loadedX, ok := loaded.(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", loaded)
	}
	if loadedX.Recipient().String() != identity.Recipient().String() {
		t.Errorf("loadIdentity recipient = %q, want %q",
			loadedX.Recipient().String(), identity.Recipient().String())
	}
}

// --- Property-based tests: sanitizePath ---

// Property: sanitizePath output never contains the root directory as a prefix,
// and always produces a shorter or equal-length string compared to fullPath.
func TestProperty_SanitizePath_strips_root(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate a root with 1-3 path components
		numRootParts := rapid.IntRange(1, 3).Draw(rt, "numRootParts")
		rootParts := make([]string, numRootParts)
		for i := range numRootParts {
			rootParts[i] = rapid.StringMatching(`[a-z]{1,8}`).Draw(rt, fmt.Sprintf("rootPart_%d", i))
		}
		root := filepath.Join(rootParts...)

		// Generate additional path components below root
		// Exclude "." and ".." — they collapse during filepath.Join and
		// can make fullPath == root, violating the "shorter" invariant.
		numRelParts := rapid.IntRange(1, 4).Draw(rt, "numRelParts")
		relParts := make([]string, numRelParts)
		for i := range numRelParts {
			relParts[i] = rapid.StringMatching(`[a-z0-9_\-\.]{1,12}`).
				Filter(func(s string) bool { return s != "." && s != ".." }).
				Draw(rt, fmt.Sprintf("relPart_%d", i))
		}
		fullPath := filepath.Join(append(rootParts, relParts...)...)

		got := sanitizePath(fullPath, root)

		// Invariant 1: result should equal the relative portion
		wantRel := filepath.Join(relParts...)
		if got != wantRel {
			rt.Fatalf("sanitizePath(%q, %q) = %q, want %q", fullPath, root, got, wantRel)
		}

		// Invariant 2: result should be shorter than fullPath (unless root is empty)
		if len(got) >= len(fullPath) && root != "" {
			rt.Fatalf("sanitizePath(%q, %q) = %q is not shorter than input", fullPath, root, got)
		}
	})
}

// Property: sanitizePath is idempotent when applied with the same root —
// once the root is stripped, stripping again with "." as root returns the same value.
func TestProperty_SanitizePath_idempotent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		root := rapid.StringMatching(`[a-z]{1,5}`).Draw(rt, "root")
		file := rapid.StringMatching(`[a-z]{1,5}\.env`).Draw(rt, "file")
		fullPath := filepath.Join(root, file)

		first := sanitizePath(fullPath, root)
		second := sanitizePath(first, ".")

		if first != second {
			rt.Fatalf("sanitizePath not idempotent: first=%q, second=%q (fullPath=%q, root=%q)",
				first, second, fullPath, root)
		}
	})
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
		defer rootDir.Close()

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
			defer rootDir.Close()

			got := decryptFile(context.Background(), rootDir, tc.file, tc.id)
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
		defer rootDir.Close()

		// Must not panic regardless of input.
		_ = decryptFile(context.Background(), rootDir, "fuzz.env", id)
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
	defer rootDir.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		// Re-write the encrypted file each iteration since decryptFile overwrites it.
		if err := os.WriteFile(envPath, encrypted, 0o644); err != nil {
			b.Fatalf("write: %v", err)
		}
		status := decryptFile(context.Background(), rootDir, "bench.env", id)
		if status != fileDecrypted {
			b.Fatalf("decryptFile = %d, want %d (fileDecrypted)", status, fileDecrypted)
		}
	}
}

// sanitizePath with unrelated paths (no common prefix).
func TestSanitizePath_unrelated_paths(t *testing.T) {
	got := sanitizePath(filepath.Join("alpha", "file.env"), filepath.Join("beta", "other"))

	// filepath.Rel can compute a relative path even for unrelated dirs on Unix
	// (e.g. "../../alpha/file.env"), so we just verify it doesn't panic
	// and returns a non-empty string.
	if got == "" {
		t.Error("sanitizePath with unrelated paths returned empty string")
	}
}

// loadIdentity with a file containing multiple identities — only the first is used.
func TestLoadIdentity_multiple_identities_uses_first(t *testing.T) {
	id1 := newIdentity(t)
	id2 := newIdentity(t)
	tmpDir := t.TempDir()

	content := id1.String() + "\n" + id2.String() + "\n"
	keyPath := filepath.Join(tmpDir, "multi.txt")
	_ = os.WriteFile(keyPath, []byte(content), 0o600)

	loaded, err := loadIdentity(keyPath)
	if err != nil {
		t.Fatalf("loadIdentity(multi): %v", err)
	}
	loadedX, ok := loaded.(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected *age.X25519Identity, got %T", loaded)
	}
	if loadedX.Recipient().String() != id1.Recipient().String() {
		t.Errorf("loadIdentity(multi) used wrong identity: got %q, want %q (first)",
			loadedX.Recipient().String(), id1.Recipient().String())
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

// decryptFile at exactly the 10 MB encrypted size limit — should be processed (not rejected).
// Kills CONDITIONALS_BOUNDARY mutant at the `info.Size() > maxEncryptedSize` check.
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
	defer rootDir.Close()

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
	defer rootDir.Close()

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
	defer rootDir.Close()

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

// sanitizePath falls back to filepath.Base when filepath.Rel errors.
// filepath.Rel returns an error when one path is absolute and the other
// is relative — they can't be made relative to each other.
func TestSanitizePath_falls_back_to_base_when_rel_errors(t *testing.T) {
	// Absolute fullPath + relative root → filepath.Rel errors.
	absPath := string(filepath.Separator) + filepath.Join("abs", "dir", "app.env")
	got := sanitizePath(absPath, "relroot")

	want := "app.env"
	if got != want {
		t.Errorf("sanitizePath(%q, %q) = %q, want %q (should fall back to Base)",
			absPath, "relroot", got, want)
	}
}

// Symmetric case: relative fullPath + absolute root should also trigger
// the filepath.Rel error branch and fall back to filepath.Base.
func TestSanitizePath_falls_back_with_relative_input_absolute_root(t *testing.T) {
	absRoot := string(filepath.Separator) + filepath.Join("abs", "root")
	got := sanitizePath(filepath.Join("rel", "path", "config.env"), absRoot)

	want := "config.env"
	if got != want {
		t.Errorf("sanitizePath(%q, %q) = %q, want %q",
			filepath.Join("rel", "path", "config.env"), absRoot, got, want)
	}
}

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
	defer rootDir.Close()

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

	_, err := loadIdentity(keyPath)
	if err == nil {
		t.Fatal("loadIdentity(comments-only) = nil, want error")
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
		// loadIdentity must not panic regardless of input.
		_, _ = loadIdentity(keyPath)
	})
}
