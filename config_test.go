package main

import (
	"os"
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
			wantMode:     "subcommand",
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
			repoRoot:     "/repo/homelab",
			wantMode:     "subcommand",
			wantKeyFile:  "/age/keys.txt",
			wantRepoRoot: "/repo/homelab",
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
