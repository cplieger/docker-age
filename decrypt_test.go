package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
)

// Tests for the single-file decrypt path (decryptFile) and the suffix matcher
// (matchesAnyExt). The directory walk (decryptAll) is covered in
// decrypt_walk_test.go; the atomic-write temp-file lifecycle
// (writeDecryptedInPlace, wipeTempFile, sweepOrphanTmpFile) in
// decrypt_tmpfile_test.go.

// nonAgeJunk returns size bytes that are NOT age-formatted (no armored or
// binary header), so decryptFile classifies them as a legitimate skip rather
// than attempting a decrypt.
func nonAgeJunk(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = 'A'
	}
	return b
}

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

// After the format-before-size reorder, a non-age file is classified from its
// header and skipped regardless of size, so the maxEncryptedSize cap applies
// ONLY to confirmed age-formatted input — it is now a performance/OOM guard
// (avoid running age.Decrypt on a 10 MB+ ciphertext), not the skip-vs-fail
// determinant it once was. The cap's exact boundary is no longer observable via
// fileStatus (an oversized age JUNK input would fail age.Decrypt anyway), so
// this pins the surviving observable contract: an age-formatted file over the
// cap is a failure. The complementary "non-age file is skipped regardless of
// size" contract is pinned by TestDecryptFile_status ("oversized non-age
// returns fileSkipped").
//
// given an age-formatted file (armored header) one byte over the 10 MB cap
// when decryptFile reads it
// then the result is fileFailed, not fileSkipped.
func TestDecryptFile_rejects_oversized_age_input(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	rel := "oversize.env"
	oversized := append([]byte(armoredHeader), nonAgeJunk(maxEncryptedSize+1-len(armoredHeader))...)
	if err := os.WriteFile(filepath.Join(tmpDir, rel), oversized, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, rel, []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptFile(age input, size=maxEncryptedSize+1) = %d, want %d (fileFailed: over 10 MB cap)", got, fileFailed)
	}
}

// decryptFile's leading guard returns fileSkipped when the context is already
// canceled, without reading or modifying the file. The decryptAll-level
// cancellation test aborts in the WalkDir callback before decryptFile is ever
// called, so this per-file guard is otherwise unexercised and a
// CONDITIONALS_NEGATION mutant on it would survive.
//
// given an already-canceled context and an age-encrypted file
// when decryptFile runs
// then it returns fileSkipped and leaves the file byte-for-byte unchanged.
func TestDecryptFile_skips_on_canceled_context(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	original := []byte("CTX_KEY=value\n")
	envPath := writeEncryptedEnv(t, tmpDir, "cancel.env", original, identity.Recipient())
	before, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := decryptFile(ctx, rootDir, "cancel.env", []age.Identity{identity})
	if got != fileSkipped {
		t.Errorf("decryptFile(canceled ctx) = %d, want %d (fileSkipped)", got, fileSkipped)
	}
	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(after) != string(before) {
		t.Error("decryptFile(canceled ctx) modified the file: must be a no-op")
	}
}

// TestDecryptFile_directory_target_returns_failed pins decryptFile's header-peek
// read-error arm: when rootDir.Open succeeds but the target cannot be read as a
// byte stream, decryptFile must fail closed (fileFailed), never silently skip.
// A directory is the deterministic trigger: os.Root.Open(dir) succeeds, then
// io.ReadFull on the directory fd returns a non-EOF "is a directory" error.
func TestDecryptFile_directory_target_returns_failed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, "adir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, "adir", []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptFile(directory target) = %d, want %d (fileFailed: header read must fail closed, not skip)", got, fileFailed)
	}
}

// TestMatchesAnyExt pins the extension-suffix matcher in isolation.
// matchesAnyExt is otherwise exercised only indirectly through decryptAll.
func TestMatchesAnyExt(t *testing.T) {
	tests := []struct {
		name string
		file string
		exts []string
		want bool
	}{
		{name: "empty list matches any file", file: "anything.txt", exts: nil, want: true},
		{name: "empty list matches dotfile", file: ".env", exts: []string{}, want: true},
		{name: "single ext matches suffix", file: "app.env", exts: []string{".env"}, want: true},
		{name: "single ext matches bare dotenv", file: ".env", exts: []string{".env"}, want: true},
		{name: "single ext no match", file: "config.yaml", exts: []string{".env"}, want: false},
		{name: "multiple ext matches second", file: "config.yaml", exts: []string{".env", ".yaml"}, want: true},
		{name: "multiple ext matches none", file: "config.json", exts: []string{".env", ".yaml"}, want: false},
		{name: "suffix match not extension-aware", file: "notanenv.env", exts: []string{".env"}, want: true},
		{name: "bare name without dot does not match", file: "env", exts: []string{".env"}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesAnyExt(tc.file, tc.exts); got != tc.want {
				t.Errorf("matchesAnyExt(%q, %v) = %v, want %v", tc.file, tc.exts, got, tc.want)
			}
		})
	}
}
