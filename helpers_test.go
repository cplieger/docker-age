package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

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

// writeEncryptedEnv writes armored ciphertext at exactly <dir>/<name> and
// returns that path. Most v3 tests want a .enc source; use writeEncSource for
// the source+output pair, or this directly when the test needs ciphertext at
// a non-.enc path (e.g. the stray-ciphertext guard).
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

// writeEncSource writes an armored-encrypted ciphertext source at
// <dir>/<name>.enc and returns (src, out): the source path and the sibling
// plaintext path a decrypt pass must produce.
func writeEncSource(t *testing.T, dir, name string, content []byte, recipient age.Recipient) (src, out string) {
	t.Helper()
	out = filepath.Join(dir, name)
	src = writeEncryptedEnv(t, dir, name+encSuffix, content, recipient)
	return src, out
}

// assertSourcePreserved fails the test when the ciphertext source at src no
// longer matches want — the v3 invariant that no decrypt path ever modifies
// its source.
func assertSourcePreserved(t *testing.T, src string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source %s: %v", src, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ciphertext source %s was modified (got %d bytes, want %d)", src, len(got), len(want))
	}
}

// assertNoOutput fails the test when a plaintext sibling exists at out — used
// after failed or skipped decrypts, which must never create partial output.
func assertNoOutput(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Stat(out); err == nil {
		t.Errorf("unexpected plaintext output %s (failed/skipped decrypt must not create it)", out)
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat output %s: %v", out, err)
	}
}

// decryptAllCount adapts decryptAll to a (count, err) return for tests that
// only care about the successful-decrypt count.
func decryptAllCount(root string, identity age.Identity) (int, error) {
	res, err := decryptAll(context.Background(), root, []age.Identity{identity}, nil)
	return res.Decrypted, err
}

// decryptFileBool adapts decryptFile to a bool return for tests that only
// care whether the decrypt succeeded.
func decryptFileBool(rootDir *os.Root, rel string, identity age.Identity) bool {
	return decryptFile(context.Background(), rootDir, rel, []age.Identity{identity}) == fileDecrypted
}
