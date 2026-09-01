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
	t.Run("empty file", func(t *testing.T) {
		p := filepath.Join(tmpDir, "empty.txt")
		_ = os.WriteFile(p, []byte{}, 0o644)
		if _, err := loadIdentities(p); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("invalid content", func(t *testing.T) {
		p := filepath.Join(tmpDir, "garbage.txt")
		_ = os.WriteFile(p, []byte("not a valid age key"), 0o644)
		if _, err := loadIdentities(p); err == nil {
			t.Error("expected error")
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

// A comment-and-whitespace-only key file must return an error, whether age
// treats it as "no identities" or as a parse error.
func TestLoadIdentity_file_with_only_comments_returns_error(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "comments-only.txt")
	content := "# only a comment\n# another comment\n\n"
	if err := os.WriteFile(keyPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadIdentities(keyPath)
	if err == nil {
		t.Fatal("loadIdentities(comments-only) = nil, want error")
	}
}
