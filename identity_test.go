package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// Tests for loadIdentities (identity.go): valid single/multi-identity key
// files, the 1 MB size guard, comment-line tolerance, and error paths.

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
	t.Run("directory", func(t *testing.T) {
		_, err := loadIdentities(tmpDir)
		if err == nil || !strings.Contains(err.Error(), "read key file") {
			t.Errorf("loadIdentities(dir) error = %v, want a read key file error", err)
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		p := filepath.Join(tmpDir, "huge.txt")
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

func TestLoadIdentity_key_at_exact_size_limit(t *testing.T) {
	tmpDir := t.TempDir()

	// A key file at exactly 1 MB must not be rejected by the size guard.
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

// loadIdentities returns all identities in a multi-identity key file, all
// forwarded to age.Decrypt (key-rotation support).
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

// An empty or comments-only key file is reported as holding no identity, and any
// other parse failure as malformed without the line, which may hold a key.
func TestLoadIdentity_content_table(t *testing.T) {
	identity := newIdentity(t)
	const badLine = "AGE-SECRET-KEY-1NOTAVALIDKEYLINE"
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "empty file", content: "", wantErr: "key file holds no age identity"},
		{name: "comments and blank lines only", content: "# created: 2024-01-01T00:00:00Z\n\n  \r\n# public key: age1x\n", wantErr: "key file holds no age identity"},
		{name: "malformed line", content: "# comment\n" + badLine + "\n", wantErr: "malformed identity"},
		{name: "valid key", content: "# comment\n" + identity.String() + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "keys.txt")
			if err := os.WriteFile(keyPath, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			ids, err := loadIdentities(keyPath)
			if tt.wantErr == "" {
				if err != nil || len(ids) != 1 {
					t.Fatalf("loadIdentities = %d identities, %v; want 1, nil", len(ids), err)
				}
				return
			}
			if err == nil {
				t.Fatalf("loadIdentities = %d identities, nil; want error %q", len(ids), tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("loadIdentities error = %q, want it to contain %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), badLine) {
				t.Errorf("loadIdentities error %q echoes the key line", err)
			}
		})
	}
}
