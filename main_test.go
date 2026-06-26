package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

// Tests for main.go's dispatch and reporting layer: the single-file entry
// point (decryptSingleFile), the decrypt orchestrator (runDecrypt) across its
// pipe / target / walk modes and deploy-gate exit codes, the idle server
// (runServer), and the log/level helpers (logLevel, logDecryptResult,
// warnIfNoFilesSeen). Shared builders live in helpers_test.go.

// --- decryptSingleFile ---

func TestDecryptSingleFile(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Create an encrypted file
	tmpDir := t.TempDir()
	plaintext := []byte("secret-content\n")
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(plaintext)
	_ = w.Close()

	envFile := filepath.Join(tmpDir, "test.env")
	if err := os.WriteFile(envFile, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Decrypt the single file
	status := decryptSingleFile(context.Background(), envFile, []age.Identity{identity})
	if status != fileDecrypted {
		t.Fatalf("decryptSingleFile = %v, want fileDecrypted", status)
	}

	// Verify content
	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted content = %q, want %q", got, plaintext)
	}
}

func TestDecryptSingleFile_nonAgeSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	plainFile := filepath.Join(tmpDir, "plain.txt")
	if err := os.WriteFile(plainFile, []byte("not encrypted"), 0o644); err != nil {
		t.Fatal(err)
	}

	identity, _ := age.GenerateX25519Identity()
	status := decryptSingleFile(context.Background(), plainFile, []age.Identity{identity})
	if status != fileSkipped {
		t.Errorf("decryptSingleFile(plaintext) = %v, want fileSkipped", status)
	}
}

// TestDecryptSingleFile_parent_not_a_directory_returns_failed covers
// decryptSingleFile's os.OpenRoot-failure branch (main.go:144-146), previously
// uncovered (decryptSingleFile 75.0%). decryptSingleFile confines I/O to the
// named file's parent via os.OpenRoot(filepath.Dir(path)); when that parent is
// not a directory, OpenRoot fails (ENOTDIR) and the function must fail the file
// gracefully (fileFailed) rather than panic. The branch is deterministically
// reached by naming a target whose parent path component is a regular file.
func TestDecryptSingleFile_parent_not_a_directory_returns_failed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	// A regular file standing in for a parent directory.
	notDir := filepath.Join(tmpDir, "regular")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// filepath.Dir(bogus) == notDir (a regular file) -> os.OpenRoot fails (ENOTDIR).
	bogus := filepath.Join(notDir, "child.env")

	got := decryptSingleFile(context.Background(), bogus, []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptSingleFile(parent not a directory) = %d, want %d (fileFailed)", got, fileFailed)
	}
}

// --- runDecrypt ---

func TestRunDecrypt_bareDecryptErrors(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()

	// No targets, no extensions = must error (not silently decrypt everything)
	cfg := &config{RepoRoot: t.TempDir()}
	code := runDecrypt(context.Background(), cfg, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(no targets, no --ext) = %d, want 1 (error)", code)
	}
}

func TestRunDecrypt_withExtWalksTree(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	tmpDir := t.TempDir()

	// Create an encrypted .env file
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, identity.Recipient())
	_, _ = w.Write([]byte("SECRET=value\n"))
	_ = w.Close()
	_ = os.WriteFile(filepath.Join(tmpDir, "app.env"), buf.Bytes(), 0o600)

	// Create an encrypted .yaml (should NOT be decrypted with --ext .env)
	var buf2 bytes.Buffer
	w2, _ := age.Encrypt(&buf2, identity.Recipient())
	_, _ = w2.Write([]byte("key: value\n"))
	_ = w2.Close()
	_ = os.WriteFile(filepath.Join(tmpDir, "config.yaml"), buf2.Bytes(), 0o600)

	// Run with --ext .env (explicit)
	cfg := &config{RepoRoot: tmpDir, Extensions: []string{".env"}}
	code := runDecrypt(context.Background(), cfg, []age.Identity{identity})
	if code != 0 {
		t.Fatalf("runDecrypt = %d, want 0", code)
	}

	// .env decrypted
	got, _ := os.ReadFile(filepath.Join(tmpDir, "app.env"))
	if string(got) != "SECRET=value\n" {
		t.Errorf(".env content = %q, want decrypted", got)
	}

	// .yaml remains encrypted
	gotYaml, _ := os.ReadFile(filepath.Join(tmpDir, "config.yaml"))
	if !bytes.HasPrefix(gotYaml, []byte(ageHeader)) {
		t.Errorf(".yaml should NOT have been decrypted, but it was")
	}
}

func TestRunDecrypt_withTargetNoExtDecryptsAll(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	tmpDir := t.TempDir()

	// Create an encrypted .yaml (explicit target path = no ext filter needed)
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, identity.Recipient())
	_, _ = w.Write([]byte("key: value\n"))
	_ = w.Close()
	yamlPath := filepath.Join(tmpDir, "config.yaml")
	_ = os.WriteFile(yamlPath, buf.Bytes(), 0o600)

	// Run with explicit target (no --ext needed)
	cfg := &config{RepoRoot: tmpDir, Targets: []string{yamlPath}}
	code := runDecrypt(context.Background(), cfg, []age.Identity{identity})
	if code != 0 {
		t.Fatalf("runDecrypt = %d, want 0", code)
	}

	got, _ := os.ReadFile(yamlPath)
	if string(got) != "key: value\n" {
		t.Errorf("explicit target content = %q, want decrypted", got)
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

// TestRunDecrypt_singleFileTarget_nonAge_exits_zero pins the documented
// single-file-target contract (README: "decrypt /path/to/file.env"): a named
// file that is NOT age-encrypted is a legitimate skip, not a failure, so the
// deploy gate sees exit 0 (re-running a deploy over an already-decrypted file
// must not block it). Exercises runDecrypt's fileSkipped arm (main.go ~106-108),
// previously uncovered.
func TestRunDecrypt_singleFileTarget_nonAge_exits_zero(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	plainPath := filepath.Join(tmpDir, "plain.env")
	if err := os.WriteFile(plainPath, []byte("PLAIN=value\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	code := runDecrypt(context.Background(), &config{Targets: []string{plainPath}}, []age.Identity{identity})
	if code != 0 {
		t.Errorf("runDecrypt(non-age single file) = %d, want 0 (skipped, not failed)", code)
	}

	got, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "PLAIN=value\n" {
		t.Errorf("non-age single file was modified: %q", got)
	}
}

// TestRunDecrypt_singleFileTarget_wrongKey_exits_one pins the deploy-gate
// failure signal for a single-file target that is age-encrypted but cannot be
// decrypted (wrong key): runDecrypt must count it Failed and return exit 1.
// Exercises runDecrypt's fileFailed arm (main.go ~104-105), previously
// uncovered.
func TestRunDecrypt_singleFileTarget_wrongKey_exits_one(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()
	encPath := writeEncryptedEnv(t, tmpDir, "secret.env", []byte("S=v\n"), encryptID.Recipient())

	code := runDecrypt(context.Background(), &config{Targets: []string{encPath}}, []age.Identity{decryptID})
	if code != 1 {
		t.Errorf("runDecrypt(wrong-key single file) = %d, want 1 (Failed > 0)", code)
	}
}

// TestRunDecrypt_dirTarget_openRoot_failure_exits_one pins the deploy-gate
// fidelity contract: when decryptAll returns a fatal error for a directory
// target (the documented "repo root unreadable" stale-mount case, or any
// os.OpenRoot failure), runDecrypt must propagate exit 1 (main.go:113-117).
// The existing TestRunSubcommand_returns_one_on_invalid_root only exercises the
// EARLIER os.Stat "target not accessible" branch (the path does not exist), not
// this decryptAll-returns-error branch (the path exists and Stats as a dir, but
// the subsequent os.OpenRoot/walk fails). A directory chmod'd to 0o000 is the
// deterministic trigger: os.Stat succeeds (stat needs no permission on the
// target itself, only on its parents) and reports IsDir, then decryptAll's
// os.OpenRoot fails with EACCES.
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
	writeEncryptedEnv(t, sub, "a.env", []byte("K=v\n"), identity.Recipient())
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })

	code := runDecrypt(context.Background(), &config{Targets: []string{sub}, Extensions: []string{".env"}}, []age.Identity{identity})
	if code != 1 {
		t.Errorf("runDecrypt(unreadable dir target) = %d, want 1 (decryptAll open-root failure must block the deploy)", code)
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

// --- run (dispatch + key-load gate) ---

// TestRun_decryptMode covers run()'s decrypt-mode dispatch and its
// loadIdentities-failure gate — the wiring between main() and runDecrypt that
// was previously uncovered (run 0%). run() installs its own signal context, so
// only the non-blocking decrypt path is exercised here; the server path
// (run -> runServer) blocks on that context by design and is covered via
// runServer directly in TestRunServer_exits_zero_on_signal.
func TestRun_decryptMode(t *testing.T) {
	t.Run("unreadable key file blocks the deploy", func(t *testing.T) {
		// A missing AGE_KEY_FILE must fail the deploy loudly (exit 1), never
		// dispatch to runDecrypt against secrets it cannot decrypt.
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
			RepoRoot:   t.TempDir(), // empty tree: nothing to decrypt, no failures
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
	cancel() // immediate signal
	code := runServer(ctx)
	if code != 0 {
		t.Errorf("runServer(canceled ctx) = %d, want 0", code)
	}
}

// --- logLevel ---

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

// --- logDecryptResult / warnIfNoFilesSeen ---

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

func TestWarnIfNoFilesSeen_warns_only_when_no_files_seen(t *testing.T) {
	tests := []struct {
		name       string
		result     decryptResult
		targets    []string
		wantSubstr string // distinguishes the repo-root vs named-target warning
		wantWarn   bool
	}{
		{name: "all zero, no targets, warns about repo root", result: decryptResult{}, targets: nil, wantWarn: true, wantSubstr: "repo_root"},
		{name: "all zero, with targets, warns about the named targets", result: decryptResult{}, targets: []string{"/foo/bar"}, wantWarn: true, wantSubstr: "targets"},
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
			warnIfNoFilesSeen(tt.result, "/repo/homelab", tt.targets)
			out := buf.String()
			gotWarn := strings.Contains(out, "no matching files found")
			if gotWarn != tt.wantWarn {
				t.Errorf("warnIfNoFilesSeen(%+v, targets=%v) warn=%v, want %v (output=%q)", tt.result, tt.targets, gotWarn, tt.wantWarn, out)
			}
			if tt.wantWarn {
				if !strings.Contains(out, "level=WARN") {
					t.Errorf("warnIfNoFilesSeen warn missing level=WARN, got %q", out)
				}
				if !strings.Contains(out, tt.wantSubstr) {
					t.Errorf("warnIfNoFilesSeen warn missing %q attr, got %q", tt.wantSubstr, out)
				}
			}
		})
	}
}
