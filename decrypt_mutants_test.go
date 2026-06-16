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

// maxEncryptedSize mirrors the unexported const in decryptFile: the 10 MB cap
// on encrypted input. Hardcoded here (DAMP) so the boundary tests read clearly.
const maxEncryptedSize = 10 << 20

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

// decryptFile reads at most maxEncryptedSize+1 bytes so that a file one byte
// over the cap is observed as oversized. Mutating the read bound to
// `maxEncryptedSize-1` (ARITHMETIC_BASE, decrypt.go:66) truncates the read to
// below the cap: the oversize check then passes and the (junk) data is treated
// as a non-age skip instead of a failure.
//
// given a non-age file exactly one byte over the 10 MB cap
// when decryptFile reads it
// then the result is fileFailed (oversized), not fileSkipped.
func TestDecryptFile_rejects_input_one_byte_over_cap(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	rel := "oversize.env"
	if err := os.WriteFile(filepath.Join(tmpDir, rel), nonAgeJunk(maxEncryptedSize+1), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, rel, []age.Identity{identity})
	if got != fileFailed {
		t.Errorf("decryptFile(size=maxEncryptedSize+1) = %d, want %d (fileFailed: over 10 MB cap)", got, fileFailed)
	}
}

// The oversize guard is `len(data) > maxEncryptedSize`. A file of exactly
// maxEncryptedSize bytes must NOT be rejected (the cap is inclusive). Mutating
// `>` to `>=` (CONDITIONALS_BOUNDARY, decrypt.go:72) rejects a file that is
// exactly at the cap, flipping the non-age skip into a failure.
//
// given a non-age file exactly at the 10 MB cap
// when decryptFile reads it
// then the result is fileSkipped (within cap, not age), not fileFailed.
func TestDecryptFile_accepts_input_exactly_at_cap(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	rel := "atcap.env"
	if err := os.WriteFile(filepath.Join(tmpDir, rel), nonAgeJunk(maxEncryptedSize), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	got := decryptFile(context.Background(), rootDir, rel, []age.Identity{identity})
	if got != fileSkipped {
		t.Errorf("decryptFile(size=maxEncryptedSize) = %d, want %d (fileSkipped: within cap, not age)", got, fileSkipped)
	}
}

// sweepOrphanTmpFile returns true only after it has actually removed a stale
// tmp file: the success path runs when `rmErr != nil` is false. Mutating that
// guard to `rmErr == nil` (CONDITIONALS_NEGATION, decrypt.go:151) makes a
// successful removal report failure (return false) — the file still gets
// removed, so only the return value distinguishes the mutant.
//
// given a stale, removable orphan tmp file
// when sweepOrphanTmpFile runs
// then it returns true and the file is gone.
func TestSweepOrphanTmpFile_returns_true_when_stale_file_removed(t *testing.T) {
	tmpDir := t.TempDir()

	rel := "abandoned.env.tmp.4242"
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

// isOrphanTmpFile validates the counter suffix digit-by-digit with
// `(r < '0' || r > '9') && r != '.'`. The lower bound `r < '0'` must keep '0'
// as a valid digit; mutating it to `r <= '0'` (CONDITIONALS_BOUNDARY,
// decrypt.go:173) wrongly rejects any suffix containing '0'. The existing
// suite covers '9' (via ".env.tmp.99999") but never a '0', leaving the lower
// boundary unkilled.
//
// given orphan tmp names whose counters include the boundary digits 0 and 9
// when isOrphanTmpFile classifies them
// then each is recognised as an orphan tmp (true).
func TestIsOrphanTmpFile_accepts_boundary_digits(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "counter is single zero", input: "app.env.tmp.0"},
		{name: "counter contains zero", input: "app.env.tmp.10"},
		{name: "pid dot counter ending in zero", input: "app.env.tmp.100.0"},
		{name: "counter is single nine", input: "app.env.tmp.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOrphanTmpFile(tc.input); !got {
				t.Errorf("isOrphanTmpFile(%q) = false, want true (digit boundary must stay valid)", tc.input)
			}
		})
	}
}

// decryptAll counts swept orphans in orphansRemoved and reports the total in
// its closing debug log. Mutating `orphansRemoved++` to `orphansRemoved--`
// (INCREMENT_DECREMENT, decrypt.go:224) logs a negative count. The count is
// not surfaced in decryptResult, so the debug log is the only observable.
//
// This test also kills the CONDITIONALS_NEGATION mutant on the root-walk-error
// guard (decrypt.go:248): flipping `rootWalkErr != nil` to `== nil` makes the
// normal (no-error) path enter the if and return early, skipping the
// "orphan tmp sweep complete" debug log entirely — so the log assertion below
// fails. rootWalkErr != nil is itself only reachable via a TOCTOU race between
// OpenRoot and WalkDir (a stale mount appearing mid-pass) and cannot be forced
// deterministically, so this skipped-log signal is what makes the mutant
// killable in a unit test.
//
// given one stale orphan tmp file in the tree
// when decryptAll completes a pass
// then its sweep-complete log reports removed=1 (not removed=-1).
func TestDecryptAll_logs_one_orphan_removed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	staleTmp := filepath.Join(tmpDir, "abandoned.env.tmp.99999")
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
