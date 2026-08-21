package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
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
	// Not parallel: capture.Default swaps the global slog default.
	rec := capture.Default(t)
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

	got := writeDecryptedSibling(t.Context(), rootDir, out+encSuffix, out, []byte("SECRET=plaintext\n"))
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

	// The publish failure is reported once, and the wipe that followed it is
	// reported not at all: an operator reading a failed deploy must be able to
	// take "temp cleanup error" as evidence that decrypted bytes really were
	// left behind, which a line emitted on every successful wipe would destroy.
	if got := rec.CountExact("rename error"); got != 1 {
		t.Errorf("rename-error records = %d, want 1 (messages=%v)", got, rec.Messages())
	}
	if got := rec.CountExact("temp cleanup error"); got != 0 {
		t.Errorf("temp-cleanup-error records = %d, want 0 (the cleanup succeeded) (messages=%v)", got, rec.Messages())
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

	got := writeDecryptedSibling(t.Context(), rootDir, "app.env"+encSuffix, "app.env", []byte("SECRET=plaintext\n"))
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

// newPlaintextTemp creates a real v3 plaintext temp holding cleartext and
// returns its relative name, the owning descriptor, and the fstat that
// identifies the inode. It exists so the three mode/cleanup tests below drive
// the actual publish primitives rather than a synthesized os.FileInfo.
func newPlaintextTemp(t *testing.T, rootDir *os.Root, outRel string, cleartext []byte) (string, *os.File, os.FileInfo) {
	t.Helper()
	tmpName, temp, err := createTempFile(rootDir, outRel)
	if err != nil {
		t.Fatalf("createTempFile: %v", err)
	}
	t.Cleanup(func() { _ = rootDir.Remove(tmpName) })
	if writeErr := writeAll(temp, cleartext); writeErr != nil {
		t.Fatalf("write cleartext: %v", writeErr)
	}
	info, err := temp.Stat()
	if err != nil {
		t.Fatalf("stat owned temp: %v", err)
	}
	return tmpName, temp, info
}

// TestValidateTempFile_refuses_a_mode_the_filesystem_widened pins that the
// publish path VERIFIES the stored mode rather than trusting the one it asked
// for. temp.Chmod(0600) is fchmod(2), and a mode argument is a request, not a
// result: on a filesystem carrying an inheritable group-write ACL (measured on
// a ZFS nfs4acl dataset) the kernel stores 0660 and fchmod still reports
// success. validateTempFile's exact-0600 comparison is the only thing standing
// between that and renaming group-readable decrypted secrets into place while
// logging "decrypted" — every other check here (regular, single-link) passes on
// a 0660 file.
//
// The drift is driven for real, by widening the inode through its own
// descriptor, and then witnessed by re-stat'ing it: a filesystem that declined
// to store 0660 makes this test INVALID rather than passing vacuously, since
// validateTempFile would be refusing a mode nothing had produced.
//
// given a plaintext temp whose stored mode is really 0660
// when validateTempFile inspects the fstat of that descriptor
// then it refuses, and names the mode it actually found.
func TestValidateTempFile_refuses_a_mode_the_filesystem_widened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: unix permission bits unreliable")
	}
	tmpDir := t.TempDir()
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	_, temp, created := newPlaintextTemp(t, rootDir, "app.env", []byte("SECRET=plaintext\n"))
	defer func() { _ = temp.Close() }()
	if perm := created.Mode().Perm(); perm != 0o600 {
		t.Fatalf("temp created with mode %04o, want 0600 before the widening", perm)
	}

	// Stand in for the filesystem storing more than fchmod asked for.
	if chmodErr := temp.Chmod(0o660); chmodErr != nil {
		t.Fatalf("widen temp mode: %v", chmodErr)
	}
	stored, err := temp.Stat()
	if err != nil {
		t.Fatalf("re-stat widened temp: %v", err)
	}
	if perm := stored.Mode().Perm(); perm != 0o660 {
		t.Skipf("INVALID: filesystem stored %04o, not 0660 — mode drift cannot be driven here, so this test would assert nothing", perm)
	}

	validateErr := validateTempFile(stored)
	if validateErr == nil {
		t.Fatalf("validateTempFile(stored mode 0660) = nil, want a refusal: publishing it leaves decrypted secrets group-readable")
	}
	if !strings.Contains(validateErr.Error(), "0660") {
		t.Errorf("validateTempFile error = %q, want it to name the stored mode 0660", validateErr)
	}
}

// TestRevalidateTempBeforeRename_refuses_a_widened_mode pins the same
// verification at the second place the publish path performs it: after the temp
// is closed and immediately before the rename. The check must read the mode
// CURRENTLY on the inode, not the one captured in `expected` when the
// descriptor was still open — a mode widened in that window (an ACL applied to
// the tree mid-pass, a neighbour's chmod) would otherwise be published as a
// group-readable plaintext sibling. The inode is unchanged, so os.SameFile
// still matches and the mode comparison is the only thing that can refuse.
//
// given an owned temp whose mode was widened to 0660 after its owning fstat
// when revalidateTempBeforeRename re-checks it
// then it refuses as unsafe and names the mode it found.
func TestRevalidateTempBeforeRename_refuses_a_widened_mode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: unix permission bits unreliable")
	}
	tmpDir := t.TempDir()
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	tmpName, temp, expected := newPlaintextTemp(t, rootDir, "app.env", []byte("SECRET=plaintext\n"))
	if closeErr := temp.Close(); closeErr != nil {
		t.Fatalf("close owned temp: %v", closeErr)
	}
	if healthy := revalidateTempBeforeRename(rootDir, tmpName, expected); healthy != nil {
		t.Fatalf("revalidateTempBeforeRename(0600 temp) = %v, want nil before the widening", healthy)
	}

	if chmodErr := os.Chmod(filepath.Join(tmpDir, tmpName), 0o660); chmodErr != nil {
		t.Fatalf("widen temp mode: %v", chmodErr)
	}
	widened, err := os.Lstat(filepath.Join(tmpDir, tmpName))
	if err != nil {
		t.Fatalf("lstat widened temp: %v", err)
	}
	if perm := widened.Mode().Perm(); perm != 0o660 {
		t.Skipf("INVALID: filesystem stored %04o, not 0660 — mode drift cannot be driven here, so this test would assert nothing", perm)
	}

	revalidateErr := revalidateTempBeforeRename(rootDir, tmpName, expected)
	if revalidateErr == nil {
		t.Fatalf("revalidateTempBeforeRename(widened to 0660) = nil, want a refusal before the rename publishes group-readable plaintext")
	}
	if !strings.Contains(revalidateErr.Error(), "0660") {
		t.Errorf("revalidateTempBeforeRename error = %q, want it to name the stored mode 0660", revalidateErr)
	}
}

// TestWipeOwnedTempFile_zeroes_the_cleartext_it_unlinks pins what happens to
// the decrypted bytes when any pre-rename check refuses — an unsafe mode, a
// failed sync, a lost inode. writeDecryptedSibling's deferred cleanup runs
// wipeOwnedTempFile on every non-committed exit, and unlinking alone is not
// enough: the name is gone but the blocks survive for anything still holding
// the inode. The wipe must truncate as well as unlink.
//
// Absence of the name is already covered end-to-end by the rename-failure test
// above; what is untested is the zeroing, which needs a second descriptor
// opened on the same inode BEFORE the wipe — that fd is how the test reads the
// inode after its directory entry is gone. It is asserted to see the cleartext
// first, so an empty read afterwards cannot come from a fixture that never
// wrote anything.
//
// given an owned plaintext temp and a witness descriptor on the same inode
// when wipeOwnedTempFile runs
// then the name is gone and the inode the witness holds reads back empty.
func TestWipeOwnedTempFile_zeroes_the_cleartext_it_unlinks(t *testing.T) {
	tmpDir := t.TempDir()
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	cleartext := []byte("SECRET=plaintext\n")
	tmpName, temp, expected := newPlaintextTemp(t, rootDir, "app.env", cleartext)
	tmpPath := filepath.Join(tmpDir, tmpName)

	witness, err := os.Open(tmpPath)
	if err != nil {
		t.Fatalf("open witness descriptor: %v", err)
	}
	defer func() { _ = witness.Close() }()
	before, err := io.ReadAll(witness)
	if err != nil {
		t.Fatalf("read witness before wipe: %v", err)
	}
	if !bytes.Equal(before, cleartext) {
		t.Fatalf("INVALID: witness read %q before the wipe, want the cleartext %q — an empty read after the wipe would prove nothing", before, cleartext)
	}

	if wipeErr := wipeOwnedTempFile(rootDir, tmpName, temp, expected); wipeErr != nil {
		t.Fatalf("wipeOwnedTempFile: %v", wipeErr)
	}

	if _, statErr := os.Lstat(tmpPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("temp name still present after wipe, lstat err = %v", statErr)
	}
	if _, seekErr := witness.Seek(0, io.SeekStart); seekErr != nil {
		t.Fatalf("rewind witness: %v", seekErr)
	}
	after, err := io.ReadAll(witness)
	if err != nil {
		t.Fatalf("read witness after wipe: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("wiped inode still holds %d bytes (%q), want it zeroed: an unlinked-but-intact inode keeps decrypted secrets readable to any open descriptor", len(after), after)
	}
}

// TestWipeOwnedTempFile_wipes_a_temp_it_was_given_no_fstat_for covers the
// cleanup shape the EARLY failures produce. writeDecryptedSibling captures the
// owning fstat only after the sync, so a write, chmod or sync error runs the
// deferred wipe with a still-open descriptor and no `expected` inode at all —
// and that is exactly the run that has decrypted plaintext sitting in a file it
// must not leave behind. The wipe has to fall back to the descriptor's own stat
// there; without it, every path check downstream has nothing to compare against
// and refuses to touch the temp, stranding the cleartext on disk.
//
// The sibling test above supplies the fstat, so it exercises the other half.
//
// given an owned plaintext temp, a witness descriptor on its inode, and no
// expected fstat
// when wipeOwnedTempFile runs
// then it succeeds, the name is gone, and the witness reads back empty.
func TestWipeOwnedTempFile_wipes_a_temp_it_was_given_no_fstat_for(t *testing.T) {
	tmpDir := t.TempDir()
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	cleartext := []byte("SECRET=plaintext\n")
	tmpName, temp, _ := newPlaintextTemp(t, rootDir, "app.env", cleartext)
	tmpPath := filepath.Join(tmpDir, tmpName)

	witness, err := os.Open(tmpPath)
	if err != nil {
		t.Fatalf("open witness descriptor: %v", err)
	}
	defer func() { _ = witness.Close() }()
	before, err := io.ReadAll(witness)
	if err != nil {
		t.Fatalf("read witness before wipe: %v", err)
	}
	if !bytes.Equal(before, cleartext) {
		t.Fatalf("INVALID: witness read %q before the wipe, want the cleartext %q — an empty read after the wipe would prove nothing", before, cleartext)
	}

	if wipeErr := wipeOwnedTempFile(rootDir, tmpName, temp, nil); wipeErr != nil {
		t.Fatalf("wipeOwnedTempFile(no expected fstat) = %v, want nil: the temp holds decrypted plaintext and must be reclaimed", wipeErr)
	}

	if _, statErr := os.Lstat(tmpPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("temp name still present after wipe, lstat err = %v", statErr)
	}
	if _, seekErr := witness.Seek(0, io.SeekStart); seekErr != nil {
		t.Fatalf("rewind witness: %v", seekErr)
	}
	after, err := io.ReadAll(witness)
	if err != nil {
		t.Fatalf("read witness after wipe: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("wiped inode still holds %d bytes (%q), want it zeroed", len(after), after)
	}
}

// TestWriteAll_reports_the_failure_the_descriptor_gave pins that the plaintext
// writer surfaces the real cause. In production the cause is a full or quota'd
// filesystem, and it reaches the operator only as the `error` attr of the
// "write error" line; substituting a generic short-write sentinel there would
// send them looking for a corrupt secret instead of a full disk. A closed
// descriptor stands in for the unwritable one: it is the one write failure a
// test can force without a filesystem that can fail.
//
// given a descriptor that cannot accept bytes
// when writeAll writes to it
// then the descriptor's own error comes back, not a substitute.
func TestWriteAll_reports_the_failure_the_descriptor_gave(t *testing.T) {
	tmpDir := t.TempDir()
	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	tmpName, temp, _ := newPlaintextTemp(t, rootDir, "app.env", nil)
	if closeErr := temp.Close(); closeErr != nil {
		t.Fatalf("close temp: %v", closeErr)
	}
	t.Cleanup(func() { _ = rootDir.Remove(tmpName) })

	err = writeAll(temp, []byte("SECRET=plaintext\n"))
	if err == nil {
		t.Fatal("writeAll(closed descriptor) = nil, want the descriptor's write error")
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("writeAll(closed descriptor) = %v, want it to carry os.ErrClosed", err)
	}
	if errors.Is(err, io.ErrShortWrite) {
		t.Errorf("writeAll(closed descriptor) = %v, want the descriptor's cause rather than a short-write substitute", err)
	}
}
