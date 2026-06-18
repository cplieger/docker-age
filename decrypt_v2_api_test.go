package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
	code := runDecrypt(cfg, []age.Identity{identity})
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
	code := runDecrypt(cfg, []age.Identity{identity})
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
	code := runDecrypt(cfg, []age.Identity{identity})
	if code != 0 {
		t.Fatalf("runDecrypt = %d, want 0", code)
	}

	got, _ := os.ReadFile(yamlPath)
	if string(got) != "key: value\n" {
		t.Errorf("explicit target content = %q, want decrypted", got)
	}
}
