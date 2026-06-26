package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Tests for the atomic-write temp-file lifecycle in decrypt.go:
// writeDecryptedInPlace (write-temp-then-rename), wipeTempFile (best-effort
// unlink with a truncate-to-zero fallback so plaintext never lingers), and
// sweepOrphanTmpFile (age-bound reclaim of temps left by a crashed run). These
// pin the security-critical "no plaintext debris" guarantees.

// TestWriteDecryptedInPlace_rename_failure_leaves_no_plaintext_debris pins the
// cleanup contract of the cycle-1-extracted writeDecryptedInPlace: when the
// rename step fails (the exact production failure mode that motivated PID-keyed
// tmp naming -- "renameat <dir>/.env.tmp <dir>/.env: no such file or
// directory"), the function must return fileFailed AND remove the 0600
// plaintext temp so no decrypted secret lingers on disk. The rename-failure
// branch (decrypt.go ~165-181) is otherwise unexercised -- existing tests cover
// only the happy path and the WriteFile-failure (read-only dir) path. A
// deterministic rename failure is forced by making rel an existing directory:
// renaming a file onto a directory fails (EISDIR).
func TestWriteDecryptedInPlace_rename_failure_leaves_no_plaintext_debris(t *testing.T) {
	tmpDir := t.TempDir()
	rel := "target"
	if err := os.Mkdir(filepath.Join(tmpDir, rel), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := writeDecryptedInPlace(rootDir, rel, []byte("SECRET=plaintext\n"))
	if got != fileFailed {
		t.Errorf("writeDecryptedInPlace(rename onto dir) = %d, want %d (fileFailed)", got, fileFailed)
	}

	// Security invariant: a failed in-place rewrite must leave no 0600 plaintext
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

// TestWipeTempFile_truncates_when_remove_blocked pins the security-critical
// defense-in-depth in wipeTempFile (decrypt.go:137-140): when the unlink of the
// 0600 plaintext temp fails for a reason OTHER than fs.ErrNotExist, the function
// must truncate the temp to zero so decrypted plaintext cannot linger on disk
// until the age-bound orphan sweep reclaims it. This fallback was previously
// uncovered (wipeTempFile 33.3%). Cycle 2 dismissed it as "equivalent-mutant
// territory -- no deterministic os.Root injection point", but that is incorrect:
// rootDir.Remove fails deterministically with EACCES under a 0o555 parent dir
// (the SAME injection point TestSweepOrphanTmpFile_returns_false_when_remove_fails
// already relies on), while truncating an existing 0o600 file needs only
// file-write permission, so the WriteFile-truncate still succeeds.
func TestWipeTempFile_truncates_when_remove_blocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod on directories unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes directory writable")
	}

	tmpDir := t.TempDir()
	rel := "leftover.env.4242.1" + tmpSuffix
	p := filepath.Join(tmpDir, rel)
	if err := os.WriteFile(p, []byte("SECRET=plaintext\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Make the parent unwritable so the unlink fails with EACCES (not
	// ErrNotExist), forcing the truncate-to-zero fallback. Truncating the
	// existing 0o600 file needs file (not dir) write permission, so it succeeds.
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	wipeTempFile(rootDir, rel)

	// Security invariant: plaintext must not linger. The unlink was blocked, so
	// the file remains -- but it must have been truncated to zero bytes.
	info, statErr := os.Stat(p)
	if statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return // removed entirely also satisfies "no plaintext lingers"
		}
		t.Fatalf("stat: %v", statErr)
	}
	if info.Size() != 0 {
		t.Errorf("wipeTempFile left %d bytes of plaintext on disk, want 0 (truncate-to-zero fallback)", info.Size())
	}
}

// TestWipeTempFile_logs_when_truncate_also_fails covers wipeTempFile's inner arm:
// when Remove fails (not ErrNotExist) AND the truncate fallback also fails,
// the function logs a "temp cleanup error" warning.
func TestWipeTempFile_logs_when_truncate_also_fails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod on directories unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes the file writable")
	}
	tmpDir := t.TempDir()
	rel := "leftover.env.4242.1" + tmpSuffix
	p := filepath.Join(tmpDir, rel)
	if err := os.WriteFile(p, []byte("SECRET=plaintext\n"), 0o400); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 0o555 parent: unlink fails EACCES. 0o400 temp: truncate fails EACCES too.
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	wipeTempFile(rootDir, rel)

	if out := buf.String(); !strings.Contains(out, "temp cleanup error") {
		t.Errorf("wipeTempFile(remove+truncate both fail) log = %q, want a 'temp cleanup error' warning", out)
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
