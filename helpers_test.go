package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Shared test helpers for the age-decrypt package. Construction builders and
// the two pre-refactor return-shape adapters live here so every per-source
// test file (decrypt, identity, config, main) can use them without hoisting
// them into a single catch-all file.

// encryptArmored encrypts data with age armor format (ASCII-safe).
func encryptArmored(data []byte, recipient age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encryptBinary encrypts data with age binary format.
func encryptBinary(data []byte, recipient age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// newIdentity generates a fresh X25519 identity for testing.
func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

// writeEncryptedEnv writes an armored-encrypted .env file and returns
// the original plaintext content.
func writeEncryptedEnv(t *testing.T, dir, name string, content []byte, recipient age.Recipient) string {
	t.Helper()
	encrypted, err := encryptArmored(content, recipient)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, encrypted, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// decryptAllCount is a test-local adapter that preserves the pre-refactor
// (count, err) shape for tests that only care about the successful-decrypt
// count. New tests that need to assert on failures should call decryptAll
// directly and use the decryptResult struct fields. Uses a background
// context; tests that need cancellation should call decryptAll directly.
func decryptAllCount(root string, identity age.Identity) (int, error) {
	res, err := decryptAll(context.Background(), root, []age.Identity{identity}, nil)
	return res.Decrypted, err
}

// decryptFileBool is a test-local adapter that preserves the pre-refactor
// bool return for existing tests. New tests that need to distinguish
// fileSkipped from fileFailed should call decryptFile directly.
func decryptFileBool(rootDir *os.Root, rel string, identity age.Identity) bool {
	return decryptFile(context.Background(), rootDir, rel, []age.Identity{identity}) == fileDecrypted
}
