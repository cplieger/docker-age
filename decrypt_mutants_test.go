package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// These tests pin specific boundary/branch behaviours in decrypt.go that the
// broader suite exercised only indirectly, leaving mutation-test gaps. Each
// test is written to fail under exactly one mutation of the targeted line and
// pass against the real code.

// nonAgeJunk returns size bytes that are NOT age-formatted (no armored or
// binary header), so decryptFile classifies them as a legitimate skip rather
// than attempting a decrypt.
func nonAgeJunk(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = 'A'
	}
	return b
}

// After the format-before-size reorder, a non-age file is classified from its
// header and skipped regardless of size, so the maxEncryptedSize cap applies
// ONLY to confirmed age-formatted input — it is now a performance/OOM guard
// (avoid running age.Decrypt on a 10 MB+ ciphertext), not the skip-vs-fail
// determinant it once was. The cap's exact boundary is no longer observable via
// fileStatus (an oversized age JUNK input would fail age.Decrypt anyway), so
// this pins the surviving observable contract: an age-formatted file over the
// cap is a failure. The complementary "non-age file is skipped regardless of
// size" contract is pinned by TestDecryptFile_status ("oversized non-age
// returns fileSkipped").
//
// given an age-formatted file (armored header) one byte over the 10 MB cap
// when decryptFile reads it
// then the result is fileFailed, not fileSkipped.
func TestDecryptFile_rejects_oversized_age_input(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	rel := "oversize.env"
	oversized := append([]byte(armoredHeader), nonAgeJunk(maxEncryptedSize+1-len(armoredHeader))...)
	if err := os.WriteFile(filepath.Join(tmpDir, rel), oversized, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, rel, []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptFile(age input, size=maxEncryptedSize+1) = %d, want %d (fileFailed: over 10 MB cap)", got, fileFailed)
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

// decryptAll counts swept orphans in orphansRemoved and reports the total in
// its closing debug log. Mutating `orphansRemoved++` to `orphansRemoved--`
// (INCREMENT_DECREMENT) logs a negative count. The count is not surfaced in
// decryptResult, so the debug log is the only observable.
//
// This test also kills the CONDITIONALS_NEGATION mutant on the root-walk-error
// guard: flipping `rootWalkErr != nil` to `== nil` makes the normal (no-error)
// path enter the if and return early, skipping the "orphan tmp sweep complete"
// debug log entirely — so the log assertion below fails. rootWalkErr != nil is
// itself only reachable via a TOCTOU race between OpenRoot and WalkDir (a stale
// mount appearing mid-pass) and cannot be forced deterministically, so this
// skipped-log signal is what makes the mutant killable in a unit test.
//
// given one stale orphan tmp file in the tree
// when decryptAll completes a pass
// then its sweep-complete log reports removed=1 (not removed=-1).
func TestDecryptAll_logs_one_orphan_removed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	staleTmp := filepath.Join(tmpDir, "abandoned.env.99999.1"+tmpSuffix)
	if err := os.WriteFile(staleTmp, []byte("dead run"), 0o600); err != nil {
		t.Fatalf("write stale tmp: %v", err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(staleTmp, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if _, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil); err != nil {
		t.Fatalf("decryptAll: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "removed=1") {
		t.Errorf("decryptAll sweep log missing removed=1, got %q", out)
	}
	if strings.Contains(out, "removed=-1") {
		t.Errorf("decryptAll sweep log reported negative count removed=-1, got %q", out)
	}
}

// decryptFile's leading guard returns fileSkipped when the context is already
// canceled, without reading or modifying the file. The decryptAll-level
// cancellation test aborts in the WalkDir callback before decryptFile is ever
// called, so this per-file guard is otherwise unexercised and a
// CONDITIONALS_NEGATION mutant on it would survive.
//
// given an already-canceled context and an age-encrypted file
// when decryptFile runs
// then it returns fileSkipped and leaves the file byte-for-byte unchanged.
func TestDecryptFile_skips_on_canceled_context(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	original := []byte("CTX_KEY=value\n")
	envPath := writeEncryptedEnv(t, tmpDir, "cancel.env", original, identity.Recipient())
	before, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := decryptFile(ctx, rootDir, "cancel.env", []age.Identity{identity})
	if got != fileSkipped {
		t.Errorf("decryptFile(canceled ctx) = %d, want %d (fileSkipped)", got, fileSkipped)
	}
	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(after) != string(before) {
		t.Error("decryptFile(canceled ctx) modified the file: must be a no-op")
	}
}

// TestMatchesAnyExt pins the extension-suffix matcher in isolation.
// matchesAnyExt is otherwise exercised only indirectly through decryptAll.
func TestMatchesAnyExt(t *testing.T) {
	tests := []struct {
		name string
		file string
		exts []string
		want bool
	}{
		{name: "empty list matches any file", file: "anything.txt", exts: nil, want: true},
		{name: "empty list matches dotfile", file: ".env", exts: []string{}, want: true},
		{name: "single ext matches suffix", file: "app.env", exts: []string{".env"}, want: true},
		{name: "single ext matches bare dotenv", file: ".env", exts: []string{".env"}, want: true},
		{name: "single ext no match", file: "config.yaml", exts: []string{".env"}, want: false},
		{name: "multiple ext matches second", file: "config.yaml", exts: []string{".env", ".yaml"}, want: true},
		{name: "multiple ext matches none", file: "config.json", exts: []string{".env", ".yaml"}, want: false},
		{name: "suffix match not extension-aware", file: "notanenv.env", exts: []string{".env"}, want: true},
		{name: "bare name without dot does not match", file: "env", exts: []string{".env"}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesAnyExt(tc.file, tc.exts); got != tc.want {
				t.Errorf("matchesAnyExt(%q, %v) = %v, want %v", tc.file, tc.exts, got, tc.want)
			}
		})
	}
}

// TestDecryptFile_directory_target_returns_failed pins decryptFile's header-peek
// read-error arm: when rootDir.Open succeeds but the target cannot be read as a
// byte stream, decryptFile must fail closed (fileFailed), never silently skip.
// A directory is the deterministic trigger: os.Root.Open(dir) succeeds, then
// io.ReadFull on the directory fd returns a non-EOF "is a directory" error.
func TestDecryptFile_directory_target_returns_failed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpDir, "adir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, "adir", []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptFile(directory target) = %d, want %d (fileFailed: header read must fail closed, not skip)", got, fileFailed)
	}
}
