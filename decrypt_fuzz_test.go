package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// FuzzDecryptFile feeds arbitrary file content to decryptFile and asserts no panic.
// This exercises format detection and decryption error paths with untrusted input.
func FuzzDecryptFile(f *testing.F) {
	id, _ := age.GenerateX25519Identity()
	validArmored, _ := encryptArmored([]byte("KEY=val\n"), id.Recipient())
	validBinary, _ := encryptBinary([]byte("KEY=val\n"), id.Recipient())

	f.Add(validArmored)
	f.Add(validBinary)
	f.Add([]byte(""))
	f.Add([]byte("PLAIN=value\n"))
	f.Add([]byte(armoredHeader + "\ncorrupt\n"))
	f.Add([]byte(ageHeader + "\ncorrupt\n"))
	f.Add(bytes.Repeat([]byte("X"), 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		envPath := filepath.Join(tmpDir, "fuzz.env")
		if err := os.WriteFile(envPath, data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		rootDir, err := os.OpenRoot(tmpDir)
		if err != nil {
			t.Fatalf("OpenRoot: %v", err)
		}
		defer func() { _ = rootDir.Close() }()

		isAge := bytes.HasPrefix(data, []byte(armoredHeader)) ||
			bytes.HasPrefix(data, []byte(ageHeader))

		status := decryptFile(context.Background(), rootDir, "fuzz.env", []age.Identity{id})

		// Invariant 1: result is always one of the three defined statuses.
		switch status {
		case fileSkipped, fileDecrypted, fileFailed:
		default:
			t.Fatalf("decryptFile returned undefined status %d for input %q", status, data)
		}

		// Invariant 2: input without a recognized age header is never reported
		// as decrypted and is left byte-for-byte unchanged on disk.
		if !isAge {
			if status == fileDecrypted {
				t.Errorf("non-age input reported fileDecrypted (input %q)", data)
			}
			after, readErr := os.ReadFile(envPath)
			if readErr != nil {
				t.Fatalf("read back: %v", readErr)
			}
			if !bytes.Equal(after, data) {
				t.Errorf("non-age input was modified on disk: got %q, want %q", after, data)
			}
		}

		// Invariant 3: regardless of outcome, no temp debris is ever left behind.
		entries, readErr := os.ReadDir(tmpDir)
		if readErr != nil {
			t.Fatalf("readdir: %v", readErr)
		}
		for _, e := range entries {
			if isOrphanTmpFile(e.Name()) {
				t.Errorf("decryptFile left tmp debris %q (input %q)", e.Name(), data)
			}
		}
	})
}
