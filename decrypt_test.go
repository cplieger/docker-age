package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
)

// Tests for the single-file decrypt path (decryptFile), the output-path
// derivation (outputRelFor), and the suffix matcher (matchesAnyExt). The
// directory walk (decryptAll) is covered in decrypt_walk_test.go; the
// atomic-write temp-file lifecycle (writeDecryptedSibling, wipeTempFile,
// sweepOrphanTmpFile) in decrypt_tmpfile_test.go.

func TestDecryptFile_decrypts_binary_format_to_sibling(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("BINARY_SECRET=value123\n")
	encrypted, err := encryptBinary(original, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	srcPath := filepath.Join(tmpDir, "binary.env"+encSuffix)
	_ = os.WriteFile(srcPath, encrypted, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "binary.env"+encSuffix, identity)
	if !got {
		t.Error("decryptFile(binary encrypted) = false, want true")
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "binary.env"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("decryptFile(binary) wrote %q, want %q", data, original)
	}
	assertSourcePreserved(t, srcPath, encrypted)
}

func TestDecryptFile_decrypts_armored_format_to_sibling(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("ARMORED_SECRET=value456\n")
	encrypted, err := encryptArmored(original, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	srcPath := filepath.Join(tmpDir, "armored.env"+encSuffix)
	_ = os.WriteFile(srcPath, encrypted, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "armored.env"+encSuffix, identity)
	if !got {
		t.Error("decryptFile(armored encrypted) = false, want true")
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "armored.env"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("decryptFile(armored) wrote %q, want %q", data, original)
	}
	assertSourcePreserved(t, srcPath, encrypted)
}

// A plaintext payload under a .enc name is a broken encrypt workflow, not a
// legitimate skip: silently copying it through (or ignoring it) would hide
// the error, so decryptFile must fail the file and create no output.
func TestDecryptFile_plaintext_enc_source_fails(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	content := []byte("PLAIN_KEY=plain_value\n")
	srcPath := filepath.Join(tmpDir, "plain.env"+encSuffix)
	_ = os.WriteFile(srcPath, content, 0o644)

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, "plain.env"+encSuffix, []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptFile(plaintext .enc) = %d, want %d (fileFailed)", got, fileFailed)
	}
	assertSourcePreserved(t, srcPath, content)
	assertNoOutput(t, filepath.Join(tmpDir, "plain.env"))
}

// A pre-existing (stale) plaintext sibling is atomically replaced by the fresh
// decrypt — the re-run path every deploy exercises: pull rotated ciphertext,
// decrypt, the output reflects the new secret.
func TestDecryptFile_overwrites_stale_output_sibling(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("ROTATED_KEY=new_value\n")
	src, out := writeEncSource(t, tmpDir, "rotate.env", original, identity.Recipient())
	if err := os.WriteFile(out, []byte("ROTATED_KEY=stale_value\n"), 0o600); err != nil {
		t.Fatalf("write stale output: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	if got := decryptFileBool(rootDir, "rotate.env"+encSuffix, identity); !got {
		t.Fatal("decryptFile = false, want true")
	}

	after, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Errorf("output = %q, want the freshly decrypted %q", after, original)
	}
	srcData, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !bytes.HasPrefix(srcData, []byte(armoredHeader)) {
		t.Error("source lost its ciphertext after the re-run")
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
	src, out := writeEncSource(t, tmpDir, "readonly.env", original, identity.Recipient())

	// Make the parent directory read-only so temp-file creation fails.
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "readonly.env"+encSuffix, identity)
	if got {
		t.Error("decryptFile(readonly dir) = true, want false (temp-file write should fail)")
	}
	assertNoOutput(t, out)
	// Source must still be intact ciphertext.
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(armoredHeader)) {
		t.Error("failed write modified the ciphertext source")
	}
}

// TestDecryptFile_status consolidates simple decryptFile status-check cases
// into a table-driven test. Each case sets up a .enc source (or not) and
// asserts the returned fileStatus; sources must survive unmodified and no
// output sibling may appear for any failing case.
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
			// v3 contract change: a plaintext payload under .enc is a broken
			// workflow, not a skip (v2 skipped non-age candidates).
			name:    "plaintext .enc returns fileFailed",
			file:    "plain.env" + encSuffix,
			content: []byte("KEY=value\n"),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "empty .enc returns fileFailed",
			file:    "empty.env" + encSuffix,
			content: []byte{},
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "single byte .enc returns fileFailed",
			file:    "tiny.env" + encSuffix,
			content: []byte("X"),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "corrupt binary header returns fileFailed",
			file:    "corrupt.env" + encSuffix,
			content: []byte(ageHeader + "\ngarbage data that is not valid age\n"),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "corrupt armored header returns fileFailed",
			file:    "corrupt.env" + encSuffix,
			content: []byte(armoredHeader + "\nthis is not valid base64 armor content\n"),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "wrong key returns fileFailed",
			file:    "wrong.env" + encSuffix,
			content: wrongKeyData,
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "missing file returns fileFailed",
			file:    "nonexistent.env" + encSuffix,
			content: nil, // don't create
			id:      decryptID,
			want:    fileFailed,
		},
		{
			name:    "oversized age input returns fileFailed",
			file:    "huge.env" + encSuffix,
			content: append([]byte(armoredHeader), bytes.Repeat([]byte("X"), 10<<20+1)...),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			// A large NON-age payload is classified from its header alone and
			// fails without being read in full (the header peek precedes the
			// size-capped read) — the outcome is fileFailed because non-age
			// content under .enc is a workflow error, but the guard against
			// reading huge files stays.
			name:    "oversized non-age .enc returns fileFailed",
			file:    "huge-plain.env" + encSuffix,
			content: bytes.Repeat([]byte("X"), 10<<20+1),
			id:      decryptID,
			want:    fileFailed,
		},
		{
			// A name that strips to nothing has no sibling to write.
			name:    "bare .enc name returns fileFailed",
			file:    encSuffix,
			content: wrongKeyData,
			id:      decryptID,
			want:    fileFailed,
		},
		{
			// A double-suffixed source would generate an output that itself
			// looks like a ciphertext source; rejected up front.
			name:    "double .enc.enc name returns fileFailed",
			file:    "app.env" + encSuffix + encSuffix,
			content: wrongKeyData,
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
			defer func() { _ = rootDir.Close() }()

			got := decryptFile(context.Background(), rootDir, tc.file, []age.Identity{tc.id})
			if got != tc.want {
				t.Errorf("decryptFile(%s) = %d, want %d", tc.name, got, tc.want)
			}
			if tc.content != nil {
				assertSourcePreserved(t, filepath.Join(tmpDir, tc.file), tc.content)
			}
		})
	}
}

// decryptFile with content that decrypts to exactly 1 MB — should succeed (not rejected).
// Kills CONDITIONALS_BOUNDARY mutant at the `len(cleartext) > maxDecryptedSize` check.
func TestDecryptFile_decrypted_content_at_exact_1MB_limit(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := bytes.Repeat([]byte("B"), 1<<20)
	_, out := writeEncSource(t, tmpDir, "exact-1mb.env", original, identity.Recipient())

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "exact-1mb.env"+encSuffix, identity)
	if !got {
		t.Error("decryptFile(exactly 1MB decrypted) = false, want true (at limit, not over)")
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) != 1<<20 {
		t.Errorf("decrypted size = %d, want %d (exactly 1MB)", len(data), 1<<20)
	}
}

// decryptFile with content that decrypts to 1 MB + 1 byte — should be rejected,
// leaving no output sibling.
func TestDecryptFile_decrypted_content_over_1MB_limit(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := bytes.Repeat([]byte("C"), 1<<20+1)
	src, out := writeEncSource(t, tmpDir, "over-1mb.env", original, identity.Recipient())

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "over-1mb.env"+encSuffix, identity)
	if got {
		t.Error("decryptFile(1MB+1 decrypted) = true, want false (over limit)")
	}
	assertNoOutput(t, out)

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(armoredHeader)) {
		t.Error("over-limit source should not have been modified")
	}
}

// decryptFile returns fileFailed when the source is stat-able but unreadable
// (mode 0 on Unix).
func TestDecryptFile_read_error_after_stat_success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod 0o000 does not block reads")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes file readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "unreadable.env"+encSuffix)
	if err := os.WriteFile(srcPath, []byte("some data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(srcPath, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(srcPath, 0o644) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFileBool(rootDir, "unreadable.env"+encSuffix, identity)
	if got {
		t.Error("decryptFile(mode=0) = true, want false (read should fail)")
	}
	assertNoOutput(t, filepath.Join(tmpDir, "unreadable.env"))
}

// TestDecryptFile_rejects_corrupted_body_leaves_source_and_no_output feeds a
// binary ciphertext whose header is valid but whose final payload chunk is
// truncated: age.Decrypt succeeds, the body fails AEAD authentication on read,
// and decryptFile must return fileFailed BEFORE the temp-write/rename, leaving
// the source byte-for-byte intact and creating no plaintext sibling. Pins the
// security invariant that a tampered body never produces partial plaintext.
func TestDecryptFile_rejects_corrupted_body_leaves_source_and_no_output(t *testing.T) {
	id := newIdentity(t)
	full, err := encryptBinary([]byte("SECRET=value\n"), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	corrupt := full[:len(full)-1]

	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "tampered.env"+encSuffix)
	if err := os.WriteFile(srcPath, corrupt, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, "tampered.env"+encSuffix, []age.Identity{id})
	if got != fileFailed {
		t.Errorf("decryptFile(corrupt body) = %d, want %d (fileFailed)", got, fileFailed)
	}
	assertSourcePreserved(t, srcPath, corrupt)
	assertNoOutput(t, filepath.Join(tmpDir, "tampered.env"))
}

// decryptFile's leading guard returns fileSkipped when the context is already
// canceled, without reading the source or creating any output.
//
// given an already-canceled context and a valid .enc source
// when decryptFile runs
// then it returns fileSkipped, the source is unchanged, and no sibling exists.
func TestDecryptFile_skips_on_canceled_context(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	original := []byte("CTX_KEY=value\n")
	src, out := writeEncSource(t, tmpDir, "cancel.env", original, identity.Recipient())
	before, err := os.ReadFile(src)
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

	got := decryptFile(ctx, rootDir, "cancel.env"+encSuffix, []age.Identity{identity})
	if got != fileSkipped {
		t.Errorf("decryptFile(canceled ctx) = %d, want %d (fileSkipped)", got, fileSkipped)
	}
	assertSourcePreserved(t, src, before)
	assertNoOutput(t, out)
}

// TestDecryptFile_directory_source_returns_failed pins decryptFile's
// header-peek read-error arm: when rootDir.Open succeeds but the target cannot
// be read as a byte stream, decryptFile must fail closed (fileFailed). A
// directory named like a source is the deterministic trigger: os.Root.Open
// succeeds, then io.ReadFull returns a non-EOF "is a directory" error.
func TestDecryptFile_directory_source_returns_failed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, "adir.env"+encSuffix), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, "adir.env"+encSuffix, []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptFile(directory source) = %d, want %d (fileFailed: header read must fail closed)", got, fileFailed)
	}
}

// TestOutputRelFor pins the source→output derivation and its three rejection
// rules (non-.enc input, bare .enc, double suffix).
func TestOutputRelFor(t *testing.T) {
	tests := []struct {
		name    string
		rel     string
		want    string
		wantErr bool
	}{
		{name: "env source", rel: "app.env" + encSuffix, want: "app.env"},
		{name: "bare dotenv source", rel: ".env" + encSuffix, want: ".env"},
		{name: "nested source", rel: "sub/dir/app.env" + encSuffix, want: "sub/dir/app.env"},
		{name: "yaml source", rel: "config.yaml" + encSuffix, want: "config.yaml"},
		{name: "no dot in stem", rel: "secrets" + encSuffix, want: "secrets"},
		{name: "non-enc input rejected", rel: "app.env", wantErr: true},
		{name: "bare .enc rejected", rel: encSuffix, wantErr: true},
		{name: "nested bare .enc rejected", rel: "sub/" + encSuffix, wantErr: true},
		{name: "double suffix rejected", rel: "app.env" + encSuffix + encSuffix, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := outputRelFor(tc.rel)
			if tc.wantErr {
				if err == nil {
					t.Errorf("outputRelFor(%q) = %q, nil — want error", tc.rel, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("outputRelFor(%q) unexpected error: %v", tc.rel, err)
			}
			if got != tc.want {
				t.Errorf("outputRelFor(%q) = %q, want %q", tc.rel, got, tc.want)
			}
		})
	}
}

// TestMatchesAnyExt pins the extension-suffix matcher in isolation. For
// ciphertext candidates the walk passes the OUTPUT name (source minus .enc),
// so these cases express the post-strip contract.
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

// The read primitive must reject final symlinks and FIFOs without following
// or blocking on either one. These are the non-regular TOCTOU replacements an
// attacker-shaped checkout can use after a walk or Lstat classification.
func TestOpenRegularReadOnly_rejects_symlink_and_fifo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlink/FIFO behavior differs")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "target"), []byte("data"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "link.env"+encSuffix)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.env"+encSuffix), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	rootDir, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	if f, err := openRegularReadOnly(rootDir, "link.env"+encSuffix); err == nil {
		_ = f.Close()
		t.Error("openRegularReadOnly(symlink) = nil error, want refusal")
	}

	done := make(chan error, 1)
	go func() {
		f, openErr := openRegularReadOnly(rootDir, "pipe.env"+encSuffix)
		if f != nil {
			_ = f.Close()
		}
		done <- openErr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("openRegularReadOnly(FIFO) = nil error, want refusal")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("openRegularReadOnly(FIFO) blocked waiting for a writer")
	}
}

// A regular hardlink can import an inode from outside the configured root
// without using a symlink. Source reads require link count one so os.Root's
// pathname confinement cannot be turned into a cross-root decryption oracle.
func TestOpenRegularReadOnly_rejects_source_with_multiple_links(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: hardlink behavior differs")
	}
	base := t.TempDir()
	rootPath := filepath.Join(base, "root")
	outsidePath := filepath.Join(base, "outside")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.WriteFile(outsidePath, []byte("ciphertext"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	insidePath := filepath.Join(rootPath, "import.env"+encSuffix)
	if err := os.Link(outsidePath, insidePath); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}

	rootDir, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()
	if f, err := openRegularReadOnly(rootDir, filepath.Base(insidePath)); err == nil {
		_ = f.Close()
		t.Fatal("openRegularReadOnly(hardlink) = nil error, want link-count refusal")
	}
	assertSourcePreserved(t, outsidePath, []byte("ciphertext"))
}
