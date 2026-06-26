package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// Tests for decryptAll, the directory-walk orchestration: per-outcome
// counting (decrypted/failed/skipped/walk_errors), the in-walk orphan-tmp
// sweep, symlink containment, multi-identity rotation, and context
// cancellation. The single-file decrypt path lives in decrypt_test.go.

func TestDecryptAllEmptyDirectory(t *testing.T) {
	identity := newIdentity(t)
	count, err := decryptAllCount(t.TempDir(), identity)
	if err != nil || count != 0 {
		t.Fatalf("empty dir: count=%d err=%v", count, err)
	}
}

func TestDecryptAllIgnoresNonEnvFiles(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, "config.txt"), []byte("data"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "settings.yaml"), []byte("data"), 0o644)

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil || count != 0 {
		t.Fatalf("non-env files: count=%d err=%v", count, err)
	}
}

func TestDecryptAllSymlinkOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlinks require elevated privileges")
	}

	identity := newIdentity(t)
	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create an encrypted .env outside the repo root
	secret := []byte("LEAKED_SECRET=bad\n")
	encrypted, err := encryptArmored(secret, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	outsideEnv := filepath.Join(outsideDir, "stolen.env")
	_ = os.WriteFile(outsideEnv, encrypted, 0o644)

	// Create a symlink inside the repo pointing outside
	symlink := filepath.Join(repoDir, "escape.env")
	if err := os.Symlink(outsideEnv, symlink); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// decryptAll should not follow the symlink to write outside the root
	count, err := decryptAllCount(repoDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}

	// The outside file should remain encrypted (not overwritten with plaintext)
	data, err := os.ReadFile(outsideEnv)
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if bytes.Equal(data, secret) {
		t.Error("symlink traversal: file outside root was decrypted in place")
	}
	_ = count // count may vary depending on os.OpenRoot behavior
}

func TestDecryptAllEnvSuffixEdgeCases(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("KEY=value\n")

	// Files that end in .env should be processed
	writeEncryptedEnv(t, tmpDir, "app.env", original, identity.Recipient())
	writeEncryptedEnv(t, tmpDir, ".env", original, identity.Recipient())

	// Files that don't end in .env should be skipped
	_ = os.WriteFile(filepath.Join(tmpDir, ".env.bak"), []byte("age-encryption.org/v1\nfake"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "env"), []byte("age-encryption.org/v1\nfake"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, ".environment"), []byte("age-encryption.org/v1\nfake"), 0o644)

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2 (only .env suffix files)", count)
	}
}

func TestDecryptAllNestedDirectories(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	sub2 := filepath.Join(tmpDir, "sub1", "sub2")
	_ = os.MkdirAll(sub2, 0o755)

	original := []byte("NESTED_KEY=nested_value\n")
	envPath := writeEncryptedEnv(t, sub2, ".env", original, identity.Recipient())

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	decrypted, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(decrypted, original) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, original)
	}
}

func TestDecryptAllWrongKey(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("SECRET=value\n")
	writeEncryptedEnv(t, tmpDir, "secret.env", original, encryptID.Recipient())

	count, err := decryptAllCount(tmpDir, decryptID)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 (wrong key should fail decryption)", count)
	}

	// File should remain encrypted (not overwritten)
	data, err := os.ReadFile(filepath.Join(tmpDir, "secret.env"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(armoredHeader)) {
		t.Error("file encrypted with different key should not have been overwritten")
	}
}

func TestDecryptAll_rejects_nonexistent_root(t *testing.T) {
	identity := newIdentity(t)
	_, err := decryptAllCount(filepath.Join(t.TempDir(), "does-not-exist"), identity)
	if err == nil {
		t.Fatal("decryptAll with non-existent root should return error")
	}
	if !strings.Contains(err.Error(), "open root") {
		t.Errorf("decryptAll error = %q, want 'open root' prefix", err.Error())
	}
}

func TestDecryptAll_skips_oversized_encrypted_file(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create a file larger than 10 MB with an age header to trigger the size guard.
	// We prepend the armored header so it passes the .env suffix check and reaches
	// the size check inside decryptFile.
	bigData := append([]byte(armoredHeader), bytes.Repeat([]byte("X"), 10<<20+1)...)
	envPath := filepath.Join(tmpDir, "huge.env")
	if err := os.WriteFile(envPath, bigData, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("decryptAll count = %d, want 0 (oversized encrypted file should be skipped)", count)
	}

	// File should remain untouched
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) <= 10<<20 {
		t.Error("oversized file was modified")
	}
}

func TestDecryptAll_handles_walk_error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: permission-based walk errors unreliable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create a subdirectory with no read permission to trigger walkErr
	noReadDir := filepath.Join(tmpDir, "noaccess")
	_ = os.MkdirAll(noReadDir, 0o755)
	_ = os.WriteFile(filepath.Join(noReadDir, "secret.env"), []byte("data"), 0o644)
	_ = os.Chmod(noReadDir, 0o000)
	defer func() { _ = os.Chmod(noReadDir, 0o755) }() // restore for cleanup

	// decryptAll should not return an error — it logs and continues
	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("decryptAll count = %d, want 0", count)
	}
}

func TestDecryptAll_handles_mixed_armored_and_binary(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	armoredContent := []byte("ARMORED_KEY=armored_value\n")
	binaryContent := []byte("BINARY_KEY=binary_value\n")

	// Write one armored-encrypted and one binary-encrypted .env file
	writeEncryptedEnv(t, tmpDir, "armored.env", armoredContent, identity.Recipient())

	binaryEncrypted, err := encryptBinary(binaryContent, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt binary: %v", err)
	}
	binaryPath := filepath.Join(tmpDir, "binary.env")
	if err := os.WriteFile(binaryPath, binaryEncrypted, 0o644); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 2 {
		t.Fatalf("decryptAll count = %d, want 2 (both armored and binary)", count)
	}

	gotArmored, err := os.ReadFile(filepath.Join(tmpDir, "armored.env"))
	if err != nil {
		t.Fatalf("read armored: %v", err)
	}
	if !bytes.Equal(gotArmored, armoredContent) {
		t.Errorf("armored decrypted = %q, want %q", gotArmored, armoredContent)
	}

	gotBinary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(gotBinary, binaryContent) {
		t.Errorf("binary decrypted = %q, want %q", gotBinary, binaryContent)
	}
}

func TestDecryptAll_respects_context_cancellation(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create a valid encrypted .env file that would normally decrypt.
	original := []byte("CANCEL_KEY=value\n")
	writeEncryptedEnv(t, tmpDir, "cancel.env", original, identity.Recipient())

	// Pass an already-canceled context — the walk should abort immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := decryptAll(ctx, tmpDir, []age.Identity{identity}, nil)
	// A canceled context aborts the walk and is reported as an error so the
	// caller (runDecrypt) exits non-zero — a pass that did not finish must
	// never look like success to the deploy gate.
	if err == nil {
		t.Fatal("decryptAll(canceled ctx) = nil error, want a cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("decryptAll(canceled ctx) err = %v, want one wrapping context.Canceled", err)
	}
	// No file should have been decrypted (the walk aborted on the first entry).
	if result.Decrypted != 0 {
		t.Errorf("decryptAll(canceled ctx) decrypted %d files, want 0", result.Decrypted)
	}
}

func TestDecryptAll_counts_failed_files(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	// One file encrypted with a different key — should fail decryption.
	writeEncryptedEnv(t, tmpDir, "wrong-key.env", []byte("SECRET=val\n"), encryptID.Recipient())

	// One plaintext .env — should be skipped (not counted as failed).
	_ = os.WriteFile(filepath.Join(tmpDir, "plain.env"), []byte("PLAIN=val\n"), 0o644)

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{decryptID}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 {
		t.Errorf("decryptAll Decrypted = %d, want 0", result.Decrypted)
	}
	if result.Failed != 1 {
		t.Errorf("decryptAll Failed = %d, want 1 (wrong-key file)", result.Failed)
	}
}

func TestDecryptAll_sweeps_orphan_tmp_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Create orphan decrypt temp files (simulating a prior SIGKILL between
	// WriteFile and Rename). Backdate them so they fall past the sweep's
	// stale threshold — young tmps are intentionally preserved now to
	// avoid ripping the tmp out from under a concurrent peer. One is a .env
	// temp, the other a non-.env (.yaml) temp the marker now also reclaims.
	orphan1 := filepath.Join(tmpDir, "app.env.111.1"+tmpSuffix)
	orphan2 := filepath.Join(tmpDir, "sub")
	_ = os.MkdirAll(orphan2, 0o755)
	orphan2File := filepath.Join(orphan2, "db.yaml.99999.2"+tmpSuffix)

	_ = os.WriteFile(orphan1, []byte("LEAKED_SECRET=bad\n"), 0o600)
	_ = os.WriteFile(orphan2File, []byte("LEAKED_DB=bad\n"), 0o600)

	oldTime := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(orphan1, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes orphan1: %v", err)
	}
	if err := os.Chtimes(orphan2File, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes orphan2: %v", err)
	}

	// Also create a valid encrypted .env to verify normal operation continues.
	original := []byte("NORMAL_KEY=value\n")
	writeEncryptedEnv(t, tmpDir, "normal.env", original, identity.Recipient())

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 1 {
		t.Errorf("decryptAll Decrypted = %d, want 1", result.Decrypted)
	}

	// Both orphan temps (.env and non-.env) should have been removed by the sweep.
	if _, err := os.Stat(orphan1); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("orphan %s should have been removed, stat err = %v", orphan1, err)
	}
	if _, err := os.Stat(orphan2File); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("orphan %s should have been removed, stat err = %v", orphan2File, err)
	}
}

// decryptAll with a directory containing only plaintext .env files — count should be 0.
func TestDecryptAll_all_plaintext_env_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	_ = os.WriteFile(filepath.Join(tmpDir, "app1.env"), []byte("KEY1=val1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "app2.env"), []byte("KEY2=val2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("ROOT_KEY=root\n"), 0o644)

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Errorf("decryptAll(all plaintext) = %d, want 0", count)
	}
}

// A file encrypted to the SECOND identity in the key file must decrypt when
// both identities are passed — this is the multi-identity key-rotation path
// (AGE_KEY_FILE documents "one identity per line"). The negative control
// (only id1) confirms the file genuinely requires id2.
func TestDecryptAll_decrypts_file_encrypted_to_second_identity(t *testing.T) {
	id1 := newIdentity(t)
	id2 := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("ROTATED_KEY=rotated_value\n")
	envPath := writeEncryptedEnv(t, tmpDir, "rotated.env", original, id2.Recipient())

	// Sanity/negative control: id1 alone cannot decrypt an id2-encrypted file.
	onlyID1, err := decryptAll(context.Background(), tmpDir, []age.Identity{id1}, nil)
	if err != nil {
		t.Fatalf("decryptAll(id1 only): %v", err)
	}
	if onlyID1.Decrypted != 0 || onlyID1.Failed != 1 {
		t.Fatalf("id1 only: Decrypted=%d Failed=%d, want 0 and 1", onlyID1.Decrypted, onlyID1.Failed)
	}

	// File is still ciphertext after the failed pass; decrypt with both keys.
	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{id1, id2}, nil)
	if err != nil {
		t.Fatalf("decryptAll(id1, id2): %v", err)
	}
	if result.Decrypted != 1 {
		t.Fatalf("Decrypted = %d, want 1 (file encrypted to 2nd identity)", result.Decrypted)
	}
	got, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("decrypted content = %q, want %q", got, original)
	}
}

// The Skipped counter must count non-age .env files (legitimate skips),
// distinct from Failed (age-formatted files that could not be decrypted).
func TestDecryptAll_counts_skipped_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Two plaintext .env files — both should be Skipped, not Failed.
	_ = os.WriteFile(filepath.Join(tmpDir, "plain1.env"), []byte("A=1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "plain2.env"), []byte("B=2\n"), 0o644)
	// One real encrypted .env — should be Decrypted.
	writeEncryptedEnv(t, tmpDir, "enc.env", []byte("C=3\n"), identity.Recipient())

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2 (two plaintext .env files)", result.Skipped)
	}
	if result.Decrypted != 1 {
		t.Errorf("Decrypted = %d, want 1", result.Decrypted)
	}
	if result.Failed != 0 {
		t.Errorf("Failed = %d, want 0 (plaintext is skipped, not failed)", result.Failed)
	}
}

// A directory the walk cannot read must increment WalkErrors (and not abort
// the whole pass). Distinct from TestDecryptAll_handles_walk_error, which only
// checks the decrypted count via the adapter.
func TestDecryptAll_counts_walk_errors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: permission-based walk errors unreliable")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes directory readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	noReadDir := filepath.Join(tmpDir, "noaccess")
	_ = os.MkdirAll(noReadDir, 0o755)
	_ = os.WriteFile(filepath.Join(noReadDir, "secret.env"), []byte("data"), 0o644)
	_ = os.Chmod(noReadDir, 0o000)
	t.Cleanup(func() { _ = os.Chmod(noReadDir, 0o755) })

	result, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.WalkErrors < 1 {
		t.Errorf("WalkErrors = %d, want >= 1 (unreadable subdir)", result.WalkErrors)
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
