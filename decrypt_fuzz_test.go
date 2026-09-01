package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// FuzzDecryptFile feeds arbitrary .enc source content to decryptFile and pins
// the sibling-output invariants: the source is never modified, non-age input
// never reports success or creates output, a success creates exactly the
// sibling, and no temp debris survives.
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
		srcRel := "fuzz.env" + encSuffix
		srcPath := filepath.Join(tmpDir, srcRel)
		outPath := filepath.Join(tmpDir, "fuzz.env")
		if err := os.WriteFile(srcPath, data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		rootDir, err := os.OpenRoot(tmpDir)
		if err != nil {
			t.Fatalf("OpenRoot: %v", err)
		}
		defer func() { _ = rootDir.Close() }()

		isAge := bytes.HasPrefix(data, []byte(armoredHeader)) ||
			bytes.HasPrefix(data, []byte(ageHeader))

		status := decryptFile(t.Context(), rootDir, srcRel, []age.Identity{id})

		switch status {
		case fileSkipped, fileDecrypted, fileFailed:
		default:
			t.Fatalf("decryptFile returned undefined status %d for input %q", status, data)
		}

		// The ciphertext source is never modified, whatever the input or
		// outcome.
		srcAfter, readErr := os.ReadFile(srcPath)
		if readErr != nil {
			t.Fatalf("read source back: %v", readErr)
		}
		if !bytes.Equal(srcAfter, data) {
			t.Errorf("source was modified on disk: got %q, want %q", srcAfter, data)
		}

		// Input without a recognized age header is never reported as
		// decrypted and never produces an output sibling.
		if !isAge {
			if status == fileDecrypted {
				t.Errorf("non-age input reported fileDecrypted (input %q)", data)
			}
			if _, statErr := os.Stat(outPath); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("non-age input produced an output sibling (input %q)", data)
			}
		}

		// A reported success means the sibling exists; a failure means it
		// does not (this harness never pre-seeds the output).
		_, statErr := os.Stat(outPath)
		switch status {
		case fileDecrypted:
			if statErr != nil {
				t.Errorf("fileDecrypted but output missing: %v", statErr)
			}
		case fileFailed, fileSkipped:
			if !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("status %d but output exists (statErr=%v)", status, statErr)
			}
		}

		// No temp debris is ever left behind, regardless of outcome.
		entries, readDirErr := os.ReadDir(tmpDir)
		if readDirErr != nil {
			t.Fatalf("readdir: %v", readDirErr)
		}
		for _, e := range entries {
			if isOrphanTmpFile(e.Name()) {
				t.Errorf("decryptFile left tmp debris %q (input %q)", e.Name(), data)
			}
		}
	})
}
