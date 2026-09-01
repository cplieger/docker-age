package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/cplieger/slogx/capture"
)

// --- decryptSingleFile ---

func TestDecryptSingleFile_writes_sibling(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	plaintext := []byte("secret-content\n")
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(plaintext)
	_ = w.Close()

	srcPath := filepath.Join(tmpDir, "test.env"+encSuffix)
	if err := os.WriteFile(srcPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	status := decryptSingleFile(t.Context(), srcPath, []age.Identity{identity})
	if status != fileDecrypted {
		t.Fatalf("decryptSingleFile = %v, want fileDecrypted", status)
	}

	got, err := os.ReadFile(filepath.Join(tmpDir, "test.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted output = %q, want %q", got, plaintext)
	}
	assertSourcePreserved(t, srcPath, buf.Bytes())
}

// A named .enc source holding plaintext is a broken workflow, not a skip: a
// .enc source must be ciphertext.
func TestDecryptSingleFile_plaintext_enc_fails(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "plain.env"+encSuffix)
	if err := os.WriteFile(srcPath, []byte("not encrypted"), 0o644); err != nil {
		t.Fatal(err)
	}

	identity := newIdentity(t)
	status := decryptSingleFile(t.Context(), srcPath, []age.Identity{identity})
	if status != fileFailed {
		t.Errorf("decryptSingleFile(plaintext .enc) = %v, want fileFailed", status)
	}
	assertNoOutput(t, filepath.Join(tmpDir, "plain.env"))
}

// A target whose parent path component is a regular file makes OpenRoot fail
// (ENOTDIR); decryptSingleFile must fail the file gracefully, not panic.
func TestDecryptSingleFile_parent_not_a_directory_returns_failed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	notDir := filepath.Join(tmpDir, "regular")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	bogus := filepath.Join(notDir, "child.env"+encSuffix)

	got := decryptSingleFile(t.Context(), bogus, []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptSingleFile(parent not a directory) = %d, want %d (fileFailed)", got, fileFailed)
	}
}

// --- runDecrypt ---

func TestRunDecrypt_bareDecryptErrors(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()

	cfg := &config{RepoRoot: t.TempDir()}
	code := runDecrypt(t.Context(), cfg, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(no targets, no --ext) = %d, want 1 (error)", code)
	}
}

func TestRunDecrypt_withExtWalksTree(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	srcEnv, outEnv := writeEncSource(t, tmpDir, "app.env", []byte("SECRET=value\n"), identity.Recipient())
	srcYaml, outYaml := writeEncSource(t, tmpDir, "config.yaml", []byte("key: value\n"), identity.Recipient())
	yamlBefore, err := os.ReadFile(srcYaml)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	cfg := &config{RepoRoot: tmpDir, Extensions: []string{".env"}}
	code := runDecrypt(t.Context(), cfg, []age.Identity{identity})
	if code != 0 {
		t.Fatalf("runDecrypt = %d, want 0", code)
	}

	got, _ := os.ReadFile(outEnv)
	if string(got) != "SECRET=value\n" {
		t.Errorf(".env output = %q, want decrypted", got)
	}

	assertSourcePreserved(t, srcYaml, yamlBefore)
	assertNoOutput(t, outYaml)
	_ = srcEnv
}

func TestRunDecrypt_withTargetNoExtDecryptsAll(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	_, out := writeEncSource(t, tmpDir, "config.yaml", []byte("key: value\n"), identity.Recipient())

	cfg := &config{RepoRoot: t.TempDir(), Targets: []string{tmpDir}}
	code := runDecrypt(t.Context(), cfg, []age.Identity{identity})
	if code != 0 {
		t.Fatalf("runDecrypt = %d, want 0", code)
	}

	got, _ := os.ReadFile(out)
	if string(got) != "key: value\n" {
		t.Errorf("explicit dir target output = %q, want decrypted", got)
	}
}

func TestRunSubcommand_returns_zero_on_success(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	writeEncSource(t, tmpDir, "app.env", []byte("SUB_KEY=value\n"), identity.Recipient())

	code := runDecrypt(t.Context(), &config{RepoRoot: tmpDir, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 0 {
		t.Errorf("runDecrypt(valid) = %d, want 0", code)
	}
}

func TestRunSubcommand_returns_one_on_decrypt_failure(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	writeEncSource(t, tmpDir, "secret.env", []byte("S=v\n"), encryptID.Recipient())

	code := runDecrypt(t.Context(), &config{RepoRoot: tmpDir, Extensions: []string{".env"}}, []age.Identity{decryptID})
	if code != 1 {
		t.Errorf("runDecrypt(wrong key) = %d, want 1 (Failed > 0)", code)
	}
}

func TestRunSubcommand_returns_one_on_invalid_root(t *testing.T) {
	identity := newIdentity(t)
	bogusRoot := filepath.Join(t.TempDir(), "does-not-exist")

	code := runDecrypt(t.Context(), &config{RepoRoot: bogusRoot, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(invalid root) = %d, want 1", code)
	}
}

// A stray ciphertext at a plaintext path (an un-migrated secret) must block
// the deploy even though every .enc source decrypted fine.
func TestRunDecrypt_stray_ciphertext_blocks_deploy(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	writeEncSource(t, tmpDir, "app.env", []byte("OK=1\n"), identity.Recipient())
	writeEncryptedEnv(t, tmpDir, "legacy.env", []byte("UNMIGRATED=1\n"), identity.Recipient())

	code := runDecrypt(t.Context(), &config{RepoRoot: tmpDir, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(stray ciphertext at legacy.env) = %d, want 1 (deploy-blocking)", code)
	}
}

// An explicit file target that does not name a .enc source is a fatal caller
// error: under the sibling-output model the tool never writes a plaintext
// path directly.
func TestRunDecrypt_singleFileTarget_nonEnc_exits_one(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	plainPath := filepath.Join(tmpDir, "plain.env")
	if err := os.WriteFile(plainPath, []byte("PLAIN=value\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	code := runDecrypt(t.Context(), &config{Targets: []string{plainPath}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(non-.enc single file) = %d, want 1 (invalid target)", code)
	}

	got, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "PLAIN=value\n" {
		t.Errorf("non-.enc target was modified: %q", got)
	}
}

func TestRunDecrypt_singleFileTarget_wrongKey_exits_one(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()
	src, _ := writeEncSource(t, tmpDir, "secret.env", []byte("S=v\n"), encryptID.Recipient())

	code := runDecrypt(t.Context(), &config{Targets: []string{src}}, []age.Identity{decryptID})
	if code != 1 {
		t.Errorf("runDecrypt(wrong-key single file) = %d, want 1 (Failed > 0)", code)
	}
}

func TestRunDecrypt_singleFileTarget_success(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	src, out := writeEncSource(t, tmpDir, "one.env", []byte("K=v\n"), identity.Recipient())

	code := runDecrypt(t.Context(), &config{Targets: []string{src}}, []age.Identity{identity})
	if code != 0 {
		t.Fatalf("runDecrypt(single .enc file) = %d, want 0", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "K=v\n" {
		t.Errorf("output = %q, want %q", got, "K=v\n")
	}
}

// A directory chmod'd to 0o000 pins the deploy-gate fidelity contract: when
// decryptAll returns a fatal error for a directory target, runDecrypt must
// propagate exit 1.
func TestRunDecrypt_dirTarget_openRoot_failure_exits_one(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: directory permissions unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes the directory readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()
	sub := filepath.Join(tmpDir, "unreadable")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeEncSource(t, sub, "a.env", []byte("K=v\n"), identity.Recipient())
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })

	code := runDecrypt(t.Context(), &config{Targets: []string{sub}, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(unreadable dir target) = %d, want 1 (decryptAll open-root failure must block the deploy)", code)
	}
}

// A subtree the walk cannot read (WalkErrors > 0) must block the deploy even
// when every source the walk DID reach decrypted cleanly — an unread subtree
// leaves its secrets undecrypted.
func TestRunDecrypt_walkError_blocks_deploy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: permission-based walk errors unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes the directory readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// A top-level source that decrypts cleanly.
	writeEncSource(t, tmpDir, "app.env", []byte("OK=1\n"), identity.Recipient())

	// An unreadable subtree hiding a source that is therefore never decrypted.
	noReadDir := filepath.Join(tmpDir, "locked")
	if err := os.MkdirAll(noReadDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeEncSource(t, noReadDir, "hidden.env", []byte("SECRET=2\n"), identity.Recipient())
	if err := os.Chmod(noReadDir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(noReadDir, 0o755) })

	code := runDecrypt(t.Context(), &config{RepoRoot: tmpDir, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(unreadable subtree, Failed=0 WalkErrors>0) = %d, want 1 (walk error must block the deploy)", code)
	}
}

// A canceled context must make runDecrypt exit non-zero on the single-file
// path, rather than report the interrupted file as a skip and exit 0.
func TestRunDecrypt_canceled_context_exits_one(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	src, _ := writeEncSource(t, tmpDir, "one.env", []byte("K=v\n"), identity.Recipient())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code := runDecrypt(ctx, &config{Targets: []string{src}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(canceled ctx, single-file target) = %d, want 1 (canceled pass must exit non-zero)", code)
	}
}

// --- run (dispatch + key-load gate) ---

// run() installs its own signal context, so only the non-blocking decrypt
// path is exercised here; the server path blocks by design and is covered
// via runServer directly.
func TestRun_decryptMode(t *testing.T) {
	t.Run("unreadable key file blocks the deploy", func(t *testing.T) {
		cfg := &config{Mode: modeDecrypt, KeyFile: filepath.Join(t.TempDir(), "missing.key")}
		if code := run(cfg); code != 1 {
			t.Errorf("run(decrypt, missing key) = %d, want 1 (loadIdentities failure must exit non-zero)", code)
		}
	})

	t.Run("valid key over an empty repo exits zero", func(t *testing.T) {
		id := newIdentity(t)
		keyPath := filepath.Join(t.TempDir(), "key.txt")
		if err := os.WriteFile(keyPath, []byte(id.String()+"\n"), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		cfg := &config{
			Mode:       modeDecrypt,
			KeyFile:    keyPath,
			RepoRoot:   t.TempDir(),
			Extensions: []string{".env"},
		}
		if code := run(cfg); code != 0 {
			t.Errorf("run(decrypt, valid key, empty repo) = %d, want 0", code)
		}
	})
}

// --- runServer (idle + signal) ---

func TestRunServer_exits_zero_on_signal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := runServer(ctx)
	if code != 0 {
		t.Errorf("runServer(canceled ctx) = %d, want 0", code)
	}
}

// --- logDecryptResult / warnIfNoFilesSeen ---

func TestLogDecryptResult_emits_all_counts(t *testing.T) {
	// Not parallel: capture.Default swaps the global slog default.
	rec := capture.Default(t)

	logDecryptResult("decryption complete", decryptResult{
		Decrypted: 3, Failed: 2, Skipped: 5, WalkErrors: 1,
	})

	if got := rec.CountExact("decryption complete"); got != 1 {
		t.Fatalf("CountExact(decryption complete) = %d, want 1 (messages=%v)", got, rec.Messages())
	}
	if got := rec.CountLevel(slog.LevelInfo, "decryption complete"); got != 1 {
		t.Errorf("CountLevel(INFO, decryption complete) = %d, want 1", got)
	}
	for key, want := range map[string]string{
		"decrypted": "3", "failed": "2", "skipped": "5", "walk_errors": "1",
	} {
		if !rec.HasAttr("decryption complete", key, want) {
			got, ok := rec.AttrValue("decryption complete", key)
			t.Errorf("summary %s = %q (found=%v), want %s", key, got, ok, want)
		}
	}
}

func TestWarnIfNoFilesSeen_warns_only_when_no_files_seen(t *testing.T) {
	tests := []struct {
		name     string
		result   decryptResult
		targets  []string
		wantAttr string // the attr key distinguishing the repo-root vs named-target warning
		wantVal  string // its rendered value (the repo root, or the fmt-rendered target list)
		wantWarn bool
	}{
		{name: "all zero, no targets, warns about repo root", result: decryptResult{}, targets: nil, wantWarn: true, wantAttr: "repo_root", wantVal: "/repo/app"},
		{name: "all zero, with targets, warns about the named targets", result: decryptResult{}, targets: []string{"/foo/bar"}, wantWarn: true, wantAttr: "targets", wantVal: "[/foo/bar]"},
		{name: "decrypted nonzero is silent", result: decryptResult{Decrypted: 1}, wantWarn: false},
		{name: "failed nonzero is silent", result: decryptResult{Failed: 1}, wantWarn: false},
		{name: "skipped nonzero is silent", result: decryptResult{Skipped: 1}, wantWarn: false},
		{name: "walk errors nonzero is silent (they already explain the empty pass)", result: decryptResult{WalkErrors: 1}, wantWarn: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel: capture.Default swaps the global slog default.
			rec := capture.Default(t)
			warnIfNoFilesSeen(tt.result, "/repo/app", tt.targets)
			gotWarn := rec.Contains("no matching files found")
			if gotWarn != tt.wantWarn {
				t.Errorf("warnIfNoFilesSeen(%+v, targets=%v) warn=%v, want %v (messages=%v)", tt.result, tt.targets, gotWarn, tt.wantWarn, rec.Messages())
			}
			if !tt.wantWarn {
				return
			}
			if rec.Len() != 1 {
				t.Fatalf("captured %d records, want exactly one warning (messages=%v)", rec.Len(), rec.Messages())
			}
			if got := rec.CountLevel(slog.LevelWarn, "no matching files found"); got != 1 {
				t.Errorf("CountLevel(WARN, no matching files found) = %d, want 1", got)
			}
			if !rec.HasAttr("no matching files found", tt.wantAttr, tt.wantVal) {
				got, ok := rec.AttrValue("no matching files found", tt.wantAttr)
				t.Errorf("warn record %s = %q (found=%v), want %q", tt.wantAttr, got, ok, tt.wantVal)
			}
		})
	}
}

// An explicit FIFO ending in .enc must be rejected without waiting for a
// writer, pinning both the Lstat gate and the nonblocking no-follow open.
func TestRunDecrypt_explicit_fifo_fails_without_blocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: FIFOs are unavailable")
	}
	identity := newIdentity(t)
	fifo := filepath.Join(t.TempDir(), "blocked.env"+encSuffix)
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan int, 1)
	go func() {
		done <- runDecrypt(t.Context(), &config{Targets: []string{fifo}}, []age.Identity{identity})
	}()
	select {
	case code := <-done:
		if code != 1 {
			t.Errorf("runDecrypt(FIFO) = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runDecrypt(FIFO) blocked waiting for a writer")
	}
}

// --ext applies to explicit files exactly as it does to walks.
func TestRunDecrypt_explicit_file_respects_ext_filter(t *testing.T) {
	identity := newIdentity(t)
	dir := t.TempDir()
	src, out := writeEncSource(t, dir, "config.yaml", []byte("key: value\n"), identity.Recipient())

	code := runDecrypt(t.Context(), &config{
		RepoRoot:   dir,
		Targets:    []string{src},
		Extensions: []string{".env"},
	}, []age.Identity{identity})
	if code != 0 {
		t.Fatalf("runDecrypt(out-of-filter explicit file) = %d, want 0", code)
	}
	assertNoOutput(t, out)
}

func TestDecryptRoot_symlinked_directory_reports_nonregular_target(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlinks require elevated privileges")
	}
	identity := newIdentity(t)
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "current")
	if err := os.Symlink("real", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := decryptRoot(t.Context(), link, []age.Identity{identity}, []string{".env"})
	if err == nil {
		t.Fatal("decryptRoot(symlinked directory) = nil error, want nonregular-target failure")
	}
	if got := err.Error(); !strings.Contains(got, "target must be a directory or a regular") {
		t.Errorf("error = %q, want nonregular target diagnostic", got)
	}
}
