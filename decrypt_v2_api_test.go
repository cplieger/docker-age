package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

// --- config parsing: --ext flags ---

func TestParseConfig_extFlags(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	tests := []struct {
		name        string
		args        []string
		wantExts    []string
		wantTargets []string
	}{
		{"no ext", []string{"age", "decrypt"}, nil, nil},
		{"single ext", []string{"age", "decrypt", "--ext", ".yaml"}, []string{".yaml"}, nil},
		{"multiple ext", []string{"age", "decrypt", "--ext", ".env", "--ext", ".yaml"}, []string{".env", ".yaml"}, []string(nil)},
		{"ext=value form", []string{"age", "decrypt", "--ext=conf"}, []string{".conf"}, nil},
		{"ext with path", []string{"age", "decrypt", "--ext", ".env", "/foo"}, []string{".env"}, []string{"/foo"}},
		{"pipe target", []string{"age", "decrypt", "-"}, nil, []string{"-"}},
		{"double dash", []string{"age", "decrypt", "--", "-weird"}, nil, []string{"-weird"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			cfg, err := parseConfig()
			if err != nil {
				t.Fatalf("parseConfig() error: %v", err)
			}
			if len(cfg.Extensions) != len(tc.wantExts) {
				t.Errorf("Extensions = %v, want %v", cfg.Extensions, tc.wantExts)
			} else {
				for i := range cfg.Extensions {
					if cfg.Extensions[i] != tc.wantExts[i] {
						t.Errorf("Extensions[%d] = %q, want %q", i, cfg.Extensions[i], tc.wantExts[i])
					}
				}
			}
			if len(cfg.Targets) != len(tc.wantTargets) {
				t.Errorf("Targets = %v, want %v", cfg.Targets, tc.wantTargets)
			}
		})
	}
}

func TestParseConfig_extDotPrefix(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	os.Args = []string{"age", "decrypt", "--ext", "yaml"}
	cfg, err := parseConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Extensions[0] != ".yaml" {
		t.Errorf("Extensions[0] = %q, want %q (should auto-prefix dot)", cfg.Extensions[0], ".yaml")
	}
}

func TestParseConfig_extRequiresValue(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	// A trailing "--ext" with no following value must error rather than index
	// past args. Exercises the bounds check so a mutated guard (which would
	// instead panic on out-of-range access or mis-parse) is caught.
	os.Args = []string{"age", "decrypt", "--ext"}
	if _, err := parseConfig(); err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Errorf("parseConfig([--ext]) = err %v, want one containing 'requires a value'", err)
	}
}

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

// --- runDecrypt with no args and no --ext errors ---

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

func TestParseConfig_rejectsUnknownFlags(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	tests := []struct {
		name string
		args []string
	}{
		{"long unknown flag", []string{"age", "decrypt", "--bogus"}},
		{"short unknown flag", []string{"age", "decrypt", "-x"}},
		{"unknown flag before path", []string{"age", "decrypt", "--nope", "/repo"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			_, err := parseConfig()
			if err == nil {
				t.Fatalf("parseConfig(%v) = nil error, want unknown-flag error", tc.args)
			}
			if !strings.Contains(err.Error(), "unknown flag") {
				t.Errorf("error = %q, want containing 'unknown flag'", err.Error())
			}
		})
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
