package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// FuzzLoadIdentity feeds arbitrary bytes as key file content to loadIdentity
// and asserts no panic. This exercises the parsing boundary for untrusted input.
func FuzzLoadIdentity(f *testing.F) {
	// Seed corpus with representative inputs.
	id, _ := age.GenerateX25519Identity()
	f.Add([]byte(id.String() + "\n"))
	f.Add([]byte("# comment\n" + id.String() + "\n"))
	f.Add([]byte(""))
	f.Add([]byte("not a valid age key\n"))
	f.Add([]byte("AGE-SECRET-KEY-1INVALID\n"))
	f.Add(bytes.Repeat([]byte("x"), 1<<20+1))

	f.Fuzz(func(t *testing.T, data []byte) {
		keyPath := filepath.Join(t.TempDir(), "fuzz-key.txt")
		if err := os.WriteFile(keyPath, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		ids, err := loadIdentities(keyPath)
		// Invariant 1: error and result are mutually exclusive.
		if err != nil {
			if ids != nil {
				t.Errorf("loadIdentities returned %d identities alongside error %v, want nil",
					len(ids), err)
			}
			return
		}

		// Invariant 2: documented success contract -- nil error guarantees at
		// least one identity and none of them is nil (forwarded verbatim to
		// variadic age.Decrypt).
		if len(ids) == 0 {
			t.Errorf("loadIdentities returned nil error but zero identities for input %q", data)
		}
		for i, identity := range ids {
			if identity == nil {
				t.Errorf("loadIdentities returned a nil identity at index %d for input %q", i, data)
			}
		}

		// Invariant 3: the 1 MB key-file size cap is honored -- an input larger
		// than the cap must never parse successfully.
		const maxKeyFileSize = 1 << 20
		if len(data) > maxKeyFileSize {
			t.Errorf("loadIdentities accepted an oversized %d-byte key file (cap %d)",
				len(data), maxKeyFileSize)
		}
	})
}
