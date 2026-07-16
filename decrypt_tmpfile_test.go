package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Tests for the atomic-write temp-file lifecycle in decrypt.go:
// exclusive random temp creation, descriptor-owned cleanup, and the
// age-bound orphan sweep. These pin the security-critical "never truncate a
// pre-existing inode and leave no plaintext debris" guarantees.

// TestWriteDecryptedSibling_rename_failure_leaves_no_plaintext_debris pins the
// cleanup contract: when the rename step fails, the function must return
// fileFailed AND remove or zero the 0600 plaintext temp so no decrypted secret
// lingers on disk. A deterministic rename failure is forced by making the
// directory: renaming a file onto a directory fails (EISDIR).
func TestWriteDecryptedSibling_rename_failure_leaves_no_plaintext_debris(t *testing.T) {
	tmpDir := t.TempDir()
	out := "target"
	if err := os.Mkdir(filepath.Join(tmpDir, out), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := writeDecryptedSibling(context.Background(), rootDir, out+encSuffix, out, []byte("SECRET=plaintext\n"))
	if got != fileFailed {
		t.Errorf("writeDecryptedSibling(rename onto dir) = %d, want %d (fileFailed)", got, fileFailed)
	}

	// Security invariant: a failed sibling write must leave no 0600 plaintext
	// temp debris behind (any name carrying the tmpSuffix marker).
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if isOrphanTmpFile(e.Name()) {
			t.Errorf("rename-failure left plaintext temp debris: %q", e.Name())
		}
	}
}

// TestWriteDecryptedSibling_canceled_before_rename_skips_and_leaves_no_output
// pins the pre-rename cancellation guard: when the context is already canceled
// by the time the temp is ready to publish, the function must return
// fileSkipped, publish no sibling, and leave no plaintext temp debris — so a
// deploy interrupted mid-pass never leaves a decrypted secret behind its
// non-zero exit. Complements the stdin-path cancellation regression in
// decrypt_stdin_test.go.
func TestWriteDecryptedSibling_canceled_before_rename_skips_and_leaves_no_output(t *testing.T) {
	tmpDir := t.TempDir()
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before the publish decision

	got := writeDecryptedSibling(ctx, rootDir, "app.env"+encSuffix, "app.env", []byte("SECRET=plaintext\n"))
	if got != fileSkipped {
		t.Errorf("writeDecryptedSibling(canceled) = %d, want %d (fileSkipped)", got, fileSkipped)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "app.env")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("canceled publish left output app.env (err=%v), want it absent", statErr)
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if isOrphanTmpFile(e.Name()) {
			t.Errorf("canceled publish left plaintext temp debris: %q", e.Name())
		}
	}
}

// TestWriteDecryptedSibling_success_writes_0600_output pins the output file
// mode: the plaintext sibling is created via a 0600 temp renamed into place,
// so it must never be group/world-readable regardless of the source's mode.
func TestWriteDecryptedSibling_success_writes_0600_output(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: unix permission bits unreliable")
	}
	tmpDir := t.TempDir()
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := writeDecryptedSibling(context.Background(), rootDir, "app.env"+encSuffix, "app.env", []byte("SECRET=plaintext\n"))
	if got != fileDecrypted {
		t.Fatalf("writeDecryptedSibling = %d, want %d (fileDecrypted)", got, fileDecrypted)
	}
	info, err := os.Stat(filepath.Join(tmpDir, "app.env"))
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("output mode = %o, want 600", perm)
	}
}

// TestOpenExclusiveTemp_refuses_preexisting_inodes exercises the primitive
// behind every plaintext temp creation. A regular file, symlink, or hardlink
// already at the proposed name must be left byte-for-byte untouched; in
// particular, a hardlink to the ciphertext source may never be truncated.
func TestOpenExclusiveTemp_refuses_preexisting_inodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlink and hardlink behavior differs")
	}

	tests := map[string]func(t *testing.T, dir, name string) string{
		"regular file": func(t *testing.T, dir, name string) string {
			t.Helper()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("DO_NOT_TRUNCATE"), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			return path
		},
		"symlink": func(t *testing.T, dir, name string) string {
			t.Helper()
			victim := filepath.Join(dir, "victim")
			if err := os.WriteFile(victim, []byte("DO_NOT_TRUNCATE"), 0o600); err != nil {
				t.Fatalf("write victim: %v", err)
			}
			if err := os.Symlink("victim", filepath.Join(dir, name)); err != nil {
				t.Fatalf("symlink: %v", err)
			}
			return victim
		},
		"hardlink to source": func(t *testing.T, dir, name string) string {
			t.Helper()
			source := filepath.Join(dir, "app.env"+encSuffix)
			if err := os.WriteFile(source, []byte("DO_NOT_TRUNCATE"), 0o600); err != nil {
				t.Fatalf("write source: %v", err)
			}
			if err := os.Link(source, filepath.Join(dir, name)); err != nil {
				t.Fatalf("hardlink: %v", err)
			}
			return source
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			tempName := "app.env.0123456789abcdef0123456789abcdef" + tmpSuffix
			victim := setup(t, dir, tempName)
			before, err := os.ReadFile(victim)
			if err != nil {
				t.Fatalf("read before: %v", err)
			}

			rootDir, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("OpenRoot: %v", err)
			}
			defer func() { _ = rootDir.Close() }()

			f, err := openExclusiveTemp(rootDir, tempName)
			if err == nil {
				_ = f.Close()
				t.Fatal("openExclusiveTemp(pre-existing path) = nil error, want refusal")
			}
			after, readErr := os.ReadFile(victim)
			if readErr != nil {
				t.Fatalf("read after: %v", readErr)
			}
			if string(after) != string(before) {
				t.Errorf("victim changed: got %q, want %q", after, before)
			}
		})
	}
}

// A generic suffix match is too broad for a cleanup routine. Only the random
// v3 grammar and strict legacy PID/counter grammar are reserved and sweepable.
func TestIsOrphanTmpFile_strict_namespace(t *testing.T) {
	tests := map[string]bool{
		"app.env.0123456789abcdef0123456789abcdef" + tmpSuffix: true,
		"app.env.4242.1" + tmpSuffix:                           true,
		".env.1.9" + tmpSuffix:                                 true,
		"notes" + tmpSuffix:                                    false,
		"app.env.not-hex" + tmpSuffix:                          false,
		"app.env.A123456789abcdef0123456789abcdef" + tmpSuffix: false,
		"app.env.0.1" + tmpSuffix:                              false,
		"app.env.1.0" + tmpSuffix:                              false,
	}
	for name, want := range tests {
		if got := isOrphanTmpFile(name); got != want {
			t.Errorf("isOrphanTmpFile(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestSweepOrphanTmpFile_returns_false_when_remove_fails pins the remove-failure
// branch (decrypt.go:178-182): a stale orphan whose unlink fails for a reason
// other than fs.ErrNotExist (here an unwritable parent dir -> EACCES) must be
// logged and reported as not-swept (return false), with the file left in place.
// Existing sweep tests cover stat-miss, young-preserved, and successful removal
// but never a removable-stale-that-fails-to-unlink. Windows + root are skipped:
// chmod cannot revoke write for either, matching the existing chmod-based tests
// in this file.
func TestSweepOrphanTmpFile_returns_false_when_remove_fails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod on directories unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes directory writable")
	}

	tmpDir := t.TempDir()
	rel := "stale.env.4242.1" + tmpSuffix
	p := filepath.Join(tmpDir, rel)
	if err := os.WriteFile(p, []byte("plaintext orphan"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	// Make the parent unwritable so the unlink fails with EACCES (not ErrNotExist).
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := sweepOrphanTmpFile(rootDir, rel, 10*time.Minute)
	if got {
		t.Errorf("sweepOrphanTmpFile(stale, unremovable) = true, want false (remove failed)")
	}
	// File must still be present (removal failed).
	if _, statErr := os.Stat(p); errors.Is(statErr, fs.ErrNotExist) {
		t.Error("orphan unexpectedly removed despite unwritable parent dir")
	}
}

// sweepOrphanTmpFile returns true only after it has actually removed a stale
// tmp file: the success path runs when `rmErr != nil` is false. Mutating that
// guard to `rmErr == nil` (CONDITIONALS_NEGATION) makes a successful removal
// report failure (return false) — the file still gets removed, so only the
// return value distinguishes the mutant.
//
// given a stale, removable orphan tmp file
// when sweepOrphanTmpFile runs
// then it returns true and the file is gone.
func TestSweepOrphanTmpFile_returns_true_when_stale_file_removed(t *testing.T) {
	tmpDir := t.TempDir()

	rel := "abandoned.env.4242.1" + tmpSuffix
	p := filepath.Join(tmpDir, rel)
	if err := os.WriteFile(p, []byte("from a dead run"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := sweepOrphanTmpFile(rootDir, rel, 10*time.Minute)
	if !got {
		t.Errorf("sweepOrphanTmpFile(stale, removable) = false, want true (removal succeeded)")
	}
	if _, statErr := os.Stat(p); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("stale tmp still present after sweep, stat err = %v", statErr)
	}
}
