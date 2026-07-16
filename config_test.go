package main

import (
	"os"
	"strings"
	"testing"
)

// TestParseConfig exercises the os.Args mode selection plus the two
// env-var reads (AGE_KEY_FILE required, AGE_REPO_ROOT default /repo).
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name         string
		keyFile      string
		repoRoot     string
		wantMode     string
		wantKeyFile  string
		wantRepoRoot string
		args         []string
		wantErr      bool
	}{
		{
			name:         "decrypt subcommand with default repo root",
			args:         []string{"age-decrypt", "decrypt"},
			keyFile:      "/age/keys.txt",
			repoRoot:     "",
			wantMode:     "decrypt",
			wantKeyFile:  "/age/keys.txt",
			wantRepoRoot: "/repo",
		},
		{
			name:         "health subcommand",
			args:         []string{"age-decrypt", "health"},
			keyFile:      "/age/keys.txt",
			repoRoot:     "",
			wantMode:     modeHealth,
			wantKeyFile:  "/age/keys.txt",
			wantRepoRoot: "/repo",
		},
		{
			name:         "no subcommand defaults to server mode",
			args:         []string{"age-decrypt"},
			keyFile:      "/age/keys.txt",
			repoRoot:     "",
			wantMode:     "server",
			wantKeyFile:  "/age/keys.txt",
			wantRepoRoot: "/repo",
		},
		{
			name:         "explicit repo root honored",
			args:         []string{"age-decrypt", "decrypt"},
			keyFile:      "/age/keys.txt",
			repoRoot:     "/repo/app",
			wantMode:     "decrypt",
			wantKeyFile:  "/age/keys.txt",
			wantRepoRoot: "/repo/app",
		},
		{
			name:    "unknown subcommand returns error",
			args:    []string{"age-decrypt", "bogus"},
			keyFile: "/age/keys.txt",
			wantErr: true,
		},
		{
			name:    "missing key file returns error",
			args:    []string{"age-decrypt", "decrypt"},
			keyFile: "",
			wantErr: true,
		},
	}

	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			t.Setenv("AGE_KEY_FILE", tt.keyFile)
			t.Setenv("AGE_REPO_ROOT", tt.repoRoot)

			cfg, err := parseConfig()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseConfig() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseConfig() unexpected error: %v", err)
			}
			if cfg.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", cfg.Mode, tt.wantMode)
			}
			if cfg.KeyFile != tt.wantKeyFile {
				t.Errorf("KeyFile = %q, want %q", cfg.KeyFile, tt.wantKeyFile)
			}
			if cfg.RepoRoot != tt.wantRepoRoot {
				t.Errorf("RepoRoot = %q, want %q", cfg.RepoRoot, tt.wantRepoRoot)
			}
		})
	}
}

// --- config parsing: --ext flags and positional args ---

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

// TestParseConfig_extRejectsEncSuffix pins the v3 filter contract: --ext
// names the decrypted OUTPUT suffix, so a value ending in .enc (which would
// select .enc.enc sources and silently match nothing) is rejected with a
// pointer to the correct form. The bare ".enc" gets the redundancy message
// instead.
func TestParseConfig_extRejectsEncSuffix(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	tests := []struct {
		name     string
		args     []string
		wantPart string
	}{
		{"env.enc space form", []string{"age", "decrypt", "--ext", ".env.enc"}, "--ext .env"},
		{"env.enc equals form", []string{"age", "decrypt", "--ext=.env.enc"}, "--ext .env"},
		{"missing dot still normalized then rejected", []string{"age", "decrypt", "--ext", "env.enc"}, "--ext .env"},
		{"bare .enc rejected as redundant", []string{"age", "decrypt", "--ext", ".enc"}, "redundant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			_, err := parseConfig()
			if err == nil || !strings.Contains(err.Error(), tc.wantPart) {
				t.Errorf("parseConfig(%v) = err %v, want one containing %q", tc.args, err, tc.wantPart)
			}
		})
	}
}

func TestParseConfig_rejects_pathlike_or_ambiguous_ext(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	tests := map[string]string{
		"env/path":  "filename suffix",
		`env\\path`: "filename suffix",
		".env ":     "whitespace",
	}
	for ext, wantPart := range tests {
		t.Run(ext, func(t *testing.T) {
			os.Args = []string{"age", "decrypt", "--ext", ext}
			_, err := parseConfig()
			if err == nil || !strings.Contains(err.Error(), wantPart) {
				t.Errorf("parseConfig(--ext %q) = %v, want error containing %q", ext, err, wantPart)
			}
		})
	}
}

func TestParseConfig_rejects_stdin_combinations(t *testing.T) {
	t.Setenv("AGE_KEY_FILE", "/tmp/fake.key")
	tests := map[string][]string{
		"stdin with extension": {"age", "decrypt", "--ext", ".env", "-"},
		"stdin with file":      {"age", "decrypt", "-", "/tmp/file.env.enc"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			os.Args = args
			if _, err := parseConfig(); err == nil {
				t.Errorf("parseConfig(%v) = nil error, want incompatible-stdin error", args)
			}
		})
	}
}
