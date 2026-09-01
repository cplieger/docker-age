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
	"github.com/cplieger/slogx/capture"
)

// Tests for decryptAll, the directory-walk orchestration: per-outcome
// counting, candidate selection by the .enc suffix, the --ext output-name
// filter, the stray-ciphertext guard, the in-walk orphan-tmp sweep, symlink
// containment, multi-identity rotation, and context cancellation. The
// single-file decrypt path is in decrypt_test.go.

func TestDecryptAllEmptyDirectory(t *testing.T) {
	identity := newIdentity(t)
	count, err := decryptAllCount(t.TempDir(), identity)
	if err != nil || count != 0 {
		t.Fatalf("empty dir: count=%d err=%v", count, err)
	}
}

// Bare mode (no --ext) considers only .enc files: age ciphertext at a
// non-.enc path is out of scope, since the stray guard applies only under an
// explicit --ext intent.
func TestDecryptAll_bare_mode_ignores_non_enc_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, "config.txt"), []byte("data"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "settings.yaml"), []byte("data"), 0o644)
	// Age ciphertext at a non-.enc path: ignored in bare mode.
	atRest := writeEncryptedEnv(t, tmpDir, "backup.age", []byte("KEEP=encrypted\n"), identity.Recipient())
	atRestBefore, err := os.ReadFile(atRest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 || result.Failed != 0 || result.Skipped != 0 {
		t.Fatalf("bare mode over non-.enc files: %+v, want all zero", result)
	}
	assertSourcePreserved(t, atRest, atRestBefore)
}

func TestDecryptAllSymlinkOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlinks require elevated privileges")
	}

	identity := newIdentity(t)
	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	// An encrypted source outside the repo root.
	secret := []byte("LEAKED_SECRET=bad\n")
	encrypted, err := encryptArmored(secret, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	outsideSrc := filepath.Join(outsideDir, "stolen.env"+encSuffix)
	_ = os.WriteFile(outsideSrc, encrypted, 0o644)

	// A symlink inside the repo pointing outside must fail closed and never be
	// followed.
	symlink := filepath.Join(repoDir, "escape.env"+encSuffix)
	if err := os.Symlink(outsideSrc, symlink); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	result, err := decryptAll(t.Context(), repoDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 {
		t.Errorf("Decrypted = %d, want 0 (symlinked source must not be processed)", result.Decrypted)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1 (matching symlink source must fail closed)", result.Failed)
	}

	// Nothing may have been written outside the root.
	if _, err := os.Stat(filepath.Join(outsideDir, "stolen.env")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("symlink traversal: plaintext written outside the root")
	}
	assertSourcePreserved(t, outsideSrc, encrypted)
}

// A symlink at the OUTPUT path must not let the rename write through to the
// link target: rename(2) replaces the link itself, leaving the linked-to file
// outside the root untouched. v2 wrote over its candidate directly; v3 writes
// a derived output path an attacker-shaped tree could pre-seed.
func TestDecryptAll_output_symlink_is_replaced_not_followed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlinks require elevated privileges")
	}

	identity := newIdentity(t)
	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	victim := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(victim, []byte("do not clobber\n"), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	original := []byte("SECRET=value\n")
	writeEncryptedEnv(t, repoDir, "app.env"+encSuffix, original, identity.Recipient())
	if err := os.Symlink(victim, filepath.Join(repoDir, "app.env")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	result, err := decryptAll(t.Context(), repoDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 1 {
		t.Fatalf("Decrypted = %d, want 1", result.Decrypted)
	}

	// The victim outside the root is untouched.
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != "do not clobber\n" {
		t.Errorf("output symlink was followed: victim = %q", got)
	}
	// The output path is now a regular file holding the plaintext.
	info, err := os.Lstat(filepath.Join(repoDir, "app.env"))
	if err != nil {
		t.Fatalf("lstat output: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("output path is still a symlink, want a regular file replacing it")
	}
	outData, err := os.ReadFile(filepath.Join(repoDir, "app.env"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(outData, original) {
		t.Errorf("output = %q, want %q", outData, original)
	}
}

// Candidate selection is by the .enc suffix; sibling names that merely start
// the same are not candidates.
func TestDecryptAll_candidate_suffix_edge_cases(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("KEY=value\n")

	// Real candidates.
	_, out1 := writeEncSource(t, tmpDir, "app.env", original, identity.Recipient())
	_, out2 := writeEncSource(t, tmpDir, ".env", original, identity.Recipient())

	// Age-formatted content at non-.enc names is ignored in bare mode.
	_ = os.WriteFile(filepath.Join(tmpDir, ".env.bak"), []byte(ageHeader+"\nfake"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "enc"), []byte(ageHeader+"\nfake"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "xenc"), []byte(ageHeader+"\nfake"), 0o644)

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 2 {
		t.Fatalf("Decrypted = %d, want 2 (only .enc sources)", result.Decrypted)
	}
	if result.Failed != 0 {
		t.Fatalf("Failed = %d, want 0 (non-.enc fakes are out of scope in bare mode)", result.Failed)
	}
	for _, out := range []string{out1, out2} {
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read output %s: %v", out, err)
		}
		if !bytes.Equal(data, original) {
			t.Errorf("output %s = %q, want %q", out, data, original)
		}
	}
}

// The --ext filter applies to the OUTPUT name: --ext .env selects .env.enc
// sources and leaves .yaml.enc sources alone.
func TestDecryptAll_ext_filters_on_output_name(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("KEY=value\n")
	srcEnv, outEnv := writeEncSource(t, tmpDir, "app.env", original, identity.Recipient())
	srcYaml, outYaml := writeEncSource(t, tmpDir, "config.yaml", []byte("key: value\n"), identity.Recipient())
	yamlBefore, err := os.ReadFile(srcYaml)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 1 {
		t.Fatalf("Decrypted = %d, want 1 (.env only)", result.Decrypted)
	}

	data, err := os.ReadFile(outEnv)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("output = %q, want %q", data, original)
	}
	assertNoOutput(t, outYaml)
	assertSourcePreserved(t, srcYaml, yamlBefore)
	_ = srcEnv
}

// Under --ext, age ciphertext at a matching plaintext path (an un-migrated or
// misnamed secret) fails the pass: the deploy would read ciphertext at that
// path, and the file itself is left untouched.
func TestDecryptAll_stray_ciphertext_fails_pass(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	strayContent := []byte("UNMIGRATED=secret\n")
	stray := writeEncryptedEnv(t, tmpDir, "legacy.env", strayContent, identity.Recipient())
	strayBefore, err := os.ReadFile(stray)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// A healthy source alongside it still decrypts.
	_, out := writeEncSource(t, tmpDir, "app.env", []byte("OK=1\n"), identity.Recipient())

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1 (stray ciphertext at legacy.env)", result.Failed)
	}
	if result.Decrypted != 1 {
		t.Errorf("Decrypted = %d, want 1 (healthy source still processed)", result.Decrypted)
	}
	assertSourcePreserved(t, stray, strayBefore)
	if _, err := os.Stat(out); err != nil {
		t.Errorf("healthy output missing: %v", err)
	}
}

// Under --ext, plaintext at a matching non-.enc path is the expected steady
// state: counted Skipped, never Failed.
func TestDecryptAll_plaintext_outputs_count_skipped(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	_ = os.WriteFile(filepath.Join(tmpDir, "app1.env"), []byte("KEY1=val1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, "app2.env"), []byte("KEY2=val2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("ROOT_KEY=root\n"), 0o644)

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Skipped != 3 {
		t.Errorf("Skipped = %d, want 3 (three plaintext .env files)", result.Skipped)
	}
	if result.Decrypted != 0 || result.Failed != 0 {
		t.Errorf("Decrypted=%d Failed=%d, want 0 and 0", result.Decrypted, result.Failed)
	}
}

// An ext-matching file the sniff cannot read fails closed: the pass cannot
// prove the deploy-consumed path holds plaintext.
func TestDecryptAll_unreadable_ext_match_fails_closed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod 0o000 does not block reads")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod bypass makes the file readable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "app.env")
	if err := os.WriteFile(p, []byte("KEY=v\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1 (unclassifiable ext match fails closed)", result.Failed)
	}
}

func TestDecryptAllNestedDirectories(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	sub2 := filepath.Join(tmpDir, "sub1", "sub2")
	_ = os.MkdirAll(sub2, 0o755)

	original := []byte("NESTED_KEY=nested_value\n")
	_, out := writeEncSource(t, sub2, ".env", original, identity.Recipient())

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	decrypted, err := os.ReadFile(out)
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
	src, out := writeEncSource(t, tmpDir, "secret.env", original, encryptID.Recipient())
	srcBefore, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{decryptID}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 || result.Failed != 1 {
		t.Fatalf("Decrypted=%d Failed=%d, want 0 and 1 (wrong key)", result.Decrypted, result.Failed)
	}
	assertSourcePreserved(t, src, srcBefore)
	assertNoOutput(t, out)
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

func TestDecryptAll_fails_oversized_encrypted_source(t *testing.T) {
	// Not parallel: capture.Default swaps the global slog default.
	rec := capture.Default(t)
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// A source larger than 10 MB with an age header triggers the size guard.
	bigData := append([]byte(armoredHeader), bytes.Repeat([]byte("X"), 10<<20+1)...)
	srcPath := filepath.Join(tmpDir, "huge.env"+encSuffix)
	if err := os.WriteFile(srcPath, bigData, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 || result.Failed != 1 {
		t.Fatalf("Decrypted=%d Failed=%d, want 0 and 1 (oversized source)", result.Decrypted, result.Failed)
	}
	assertNoOutput(t, filepath.Join(tmpDir, "huge.env"))

	// Both this guard and a failed decrypt count the same way (one Failed), so
	// the diagnostic is the operator's only evidence for why the deploy
	// stopped. It must name the size refusal and report the bytes actually
	// read: one past the cap, never the whole file.
	if got := rec.CountExact("file exceeds max encrypted-input size, treating as failure"); got != 1 {
		t.Errorf("size-refusal records = %d, want 1 (messages=%v)", got, rec.Messages())
	}
	if !rec.HasAttr("file exceeds max encrypted-input size", "size", "10485761") {
		got, ok := rec.AttrValue("file exceeds max encrypted-input size", "size")
		t.Errorf("size attr = %q (found=%v), want 10485761 (one byte past the cap)", got, ok)
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) <= 10<<20 {
		t.Error("oversized source was modified")
	}
}

// The 10 MB encrypted-input cap is inclusive: a source of exactly that many
// bytes must reach the decrypt step rather than being turned away for size.
// The payload here is padding, so the pass still fails; what is pinned is
// that it fails at the decrypt, one guard later.
func TestDecryptAll_source_at_the_encrypted_size_cap_reaches_the_decrypt(t *testing.T) {
	// Not parallel: capture.Default swaps the global slog default.
	rec := capture.Default(t)
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	header := []byte(ageHeader + "\n")
	atCap := append(header, bytes.Repeat([]byte("X"), maxEncryptedSize-len(header))...)
	if len(atCap) != maxEncryptedSize {
		t.Fatalf("fixture is %d bytes, want exactly %d", len(atCap), maxEncryptedSize)
	}
	srcPath := filepath.Join(tmpDir, "atcap.env"+encSuffix)
	if err := os.WriteFile(srcPath, atCap, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 || result.Failed != 1 {
		t.Fatalf("Decrypted=%d Failed=%d, want 0 and 1", result.Decrypted, result.Failed)
	}
	if got := rec.CountExact("decrypt error"); got != 1 {
		t.Errorf("decrypt-error records = %d, want 1 (messages=%v)", got, rec.Messages())
	}
	if got := rec.Count("file exceeds max encrypted-input size"); got != 0 {
		t.Errorf("size-refusal records = %d, want 0: a source exactly at the cap is within it", got)
	}
	assertNoOutput(t, filepath.Join(tmpDir, "atcap.env"))
	assertSourcePreserved(t, srcPath, atCap)
}

// A directory whose name ends in .enc is a candidate by name and can never be
// one in fact. It must fail the pass rather than be silently skipped past —
// that would hand the deploy a missing secret with a clean exit. A valid
// source alongside it still decrypts.
func TestDecryptAll_directory_named_like_a_ciphertext_source_fails_closed(t *testing.T) {
	identity := newIdentity(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "bundle.env"+encSuffix), 0o755); err != nil {
		t.Fatalf("mkdir candidate directory: %v", err)
	}
	original := []byte("GOOD=value\n")
	_, out := writeEncSource(t, dir, "app.env", original, identity.Recipient())

	result, err := decryptAll(t.Context(), dir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Failed != 1 || result.Decrypted != 1 {
		t.Errorf("result = %+v, want Failed=1 (the directory) and Decrypted=1 (the real source)", result)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("output %s = %q, want %q", out, got, original)
	}
	assertNoOutput(t, filepath.Join(dir, "bundle.env"))
}

func TestDecryptAll_handles_mixed_armored_and_binary(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	armoredContent := []byte("ARMORED_KEY=armored_value\n")
	binaryContent := []byte("BINARY_KEY=binary_value\n")

	_, armoredOut := writeEncSource(t, tmpDir, "armored.env", armoredContent, identity.Recipient())

	binaryEncrypted, err := encryptBinary(binaryContent, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt binary: %v", err)
	}
	binarySrc := filepath.Join(tmpDir, "binary.env"+encSuffix)
	if err := os.WriteFile(binarySrc, binaryEncrypted, 0o644); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 2 {
		t.Fatalf("decryptAll count = %d, want 2 (both armored and binary)", count)
	}

	gotArmored, err := os.ReadFile(armoredOut)
	if err != nil {
		t.Fatalf("read armored output: %v", err)
	}
	if !bytes.Equal(gotArmored, armoredContent) {
		t.Errorf("armored decrypted = %q, want %q", gotArmored, armoredContent)
	}

	gotBinary, err := os.ReadFile(filepath.Join(tmpDir, "binary.env"))
	if err != nil {
		t.Fatalf("read binary output: %v", err)
	}
	if !bytes.Equal(gotBinary, binaryContent) {
		t.Errorf("binary decrypted = %q, want %q", gotBinary, binaryContent)
	}
	assertSourcePreserved(t, binarySrc, binaryEncrypted)
}

func TestDecryptAll_respects_context_cancellation(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("CANCEL_KEY=value\n")
	_, out := writeEncSource(t, tmpDir, "cancel.env", original, identity.Recipient())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := decryptAll(ctx, tmpDir, []age.Identity{identity}, nil)
	// A canceled context must be reported as an error so runDecrypt exits
	// non-zero — a pass that did not finish must never look like success.
	if err == nil {
		t.Fatal("decryptAll(canceled ctx) = nil error, want a cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("decryptAll(canceled ctx) err = %v, want one wrapping context.Canceled", err)
	}
	if result.Decrypted != 0 {
		t.Errorf("decryptAll(canceled ctx) decrypted %d files, want 0", result.Decrypted)
	}
	assertNoOutput(t, out)
}

func TestDecryptAll_counts_failed_and_skipped_under_ext(t *testing.T) {
	encryptID := newIdentity(t)
	decryptID := newIdentity(t)
	tmpDir := t.TempDir()

	// A source encrypted with a different key — Failed.
	writeEncSource(t, tmpDir, "wrong-key.env", []byte("SECRET=val\n"), encryptID.Recipient())
	// A plaintext .env (a generated output from an earlier pass) — Skipped.
	_ = os.WriteFile(filepath.Join(tmpDir, "plain.env"), []byte("PLAIN=val\n"), 0o644)

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{decryptID}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 {
		t.Errorf("Decrypted = %d, want 0", result.Decrypted)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1 (wrong-key source)", result.Failed)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (plaintext output)", result.Skipped)
	}
}

func TestDecryptAll_handles_walk_error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: permission-based walk errors unreliable")
	}

	identity := newIdentity(t)
	tmpDir := t.TempDir()

	noReadDir := filepath.Join(tmpDir, "noaccess")
	_ = os.MkdirAll(noReadDir, 0o755)
	_ = os.WriteFile(filepath.Join(noReadDir, "secret.env"+encSuffix), []byte("data"), 0o644)
	_ = os.Chmod(noReadDir, 0o000)
	defer func() { _ = os.Chmod(noReadDir, 0o755) }() // restore for cleanup

	// decryptAll does not error on a subtree failure — it logs, counts, and
	// continues.
	count, err := decryptAllCount(tmpDir, identity)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if count != 0 {
		t.Fatalf("decryptAll count = %d, want 0", count)
	}
}

// A directory the walk cannot read must increment WalkErrors (and not abort
// the whole pass).
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
	_ = os.WriteFile(filepath.Join(noReadDir, "secret.env"+encSuffix), []byte("data"), 0o644)
	_ = os.Chmod(noReadDir, 0o000)
	t.Cleanup(func() { _ = os.Chmod(noReadDir, 0o755) })

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.WalkErrors < 1 {
		t.Errorf("WalkErrors = %d, want >= 1 (unreadable subdir)", result.WalkErrors)
	}
}

func TestDecryptAll_sweeps_orphan_tmp_files(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Orphan decrypt temp files (simulating a prior SIGKILL between WriteFile
	// and Rename), backdated past the sweep's stale threshold.
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

	// A valid source to verify normal operation continues.
	original := []byte("NORMAL_KEY=value\n")
	writeEncSource(t, tmpDir, "normal.env", original, identity.Recipient())

	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil)
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 1 {
		t.Errorf("decryptAll Decrypted = %d, want 1", result.Decrypted)
	}

	if _, err := os.Stat(orphan1); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("orphan %s should have been removed, stat err = %v", orphan1, err)
	}
	if _, err := os.Stat(orphan2File); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("orphan %s should have been removed, stat err = %v", orphan2File, err)
	}
}

// A source encrypted to the SECOND identity in the key file must decrypt when
// both identities are passed (the multi-identity key-rotation path). The
// negative control (only id1) confirms the file genuinely requires id2.
func TestDecryptAll_decrypts_file_encrypted_to_second_identity(t *testing.T) {
	id1 := newIdentity(t)
	id2 := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("ROTATED_KEY=rotated_value\n")
	_, out := writeEncSource(t, tmpDir, "rotated.env", original, id2.Recipient())

	// Sanity/negative control: id1 alone cannot decrypt an id2-encrypted file.
	onlyID1, err := decryptAll(t.Context(), tmpDir, []age.Identity{id1}, nil)
	if err != nil {
		t.Fatalf("decryptAll(id1 only): %v", err)
	}
	if onlyID1.Decrypted != 0 || onlyID1.Failed != 1 {
		t.Fatalf("id1 only: Decrypted=%d Failed=%d, want 0 and 1", onlyID1.Decrypted, onlyID1.Failed)
	}
	assertNoOutput(t, out)

	// The source is intact ciphertext; decrypt with both keys.
	result, err := decryptAll(t.Context(), tmpDir, []age.Identity{id1, id2}, nil)
	if err != nil {
		t.Fatalf("decryptAll(id1, id2): %v", err)
	}
	if result.Decrypted != 1 {
		t.Fatalf("Decrypted = %d, want 1 (file encrypted to 2nd identity)", result.Decrypted)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("decrypted content = %q, want %q", got, original)
	}
}

// Re-running a pass over an already-decrypted tree is stable: the source is
// re-decrypted, the output is refreshed with identical content, and nothing
// errors.
func TestDecryptAll_rerun_is_stable(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("RERUN_KEY=value\n")
	src, out := writeEncSource(t, tmpDir, "app.env", original, identity.Recipient())
	srcBefore, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	for pass := 1; pass <= 2; pass++ {
		result, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, []string{".env"})
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if result.Decrypted != 1 || result.Failed != 0 {
			t.Fatalf("pass %d: Decrypted=%d Failed=%d, want 1 and 0", pass, result.Decrypted, result.Failed)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("pass %d read output: %v", pass, err)
		}
		if !bytes.Equal(got, original) {
			t.Errorf("pass %d output = %q, want %q", pass, got, original)
		}
		assertSourcePreserved(t, src, srcBefore)
	}
}

// decryptAll counts swept orphans in orphansRemoved and reports the total in
// its closing debug log; a negative count would mean the counter direction
// flipped. The sweep-complete log only fires on the no-walk-error path, so
// this also pins that guard's polarity.
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

	if _, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil); err != nil {
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

// Invalid .enc-shaped names are workflow failures even when --ext would not
// select their derived output: validation must precede filtering.
func TestDecryptAll_invalid_enc_names_fail_before_ext_filter(t *testing.T) {
	identity := newIdentity(t)
	dir := t.TempDir()
	for _, name := range []string{encSuffix, "app.env" + encSuffix + encSuffix} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("invalid"), 0o600); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}

	result, err := decryptAll(t.Context(), dir, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Failed != 2 || result.Decrypted != 0 {
		t.Errorf("result = %+v, want Failed=2 and Decrypted=0", result)
	}
}

// Matching symlinks are not silently ignored: a .enc symlink cannot be a
// trusted ciphertext source, and neither can a symlink at a plaintext path.
func TestDecryptAll_matching_symlinks_fail_closed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: symlinks require elevated privileges")
	}
	identity := newIdentity(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cipher.bin"), []byte("not read"), 0o600); err != nil {
		t.Fatalf("write source target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("not read"), 0o600); err != nil {
		t.Fatalf("write output target: %v", err)
	}
	if err := os.Symlink("cipher.bin", filepath.Join(dir, "source.env"+encSuffix)); err != nil {
		t.Fatalf("symlink source: %v", err)
	}
	if err := os.Symlink("plain.txt", filepath.Join(dir, "legacy.env")); err != nil {
		t.Fatalf("symlink output: %v", err)
	}

	result, err := decryptAll(t.Context(), dir, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Failed != 2 || result.Decrypted != 0 {
		t.Errorf("result = %+v, want Failed=2 and Decrypted=0", result)
	}
}

// A stale ciphertext output sorts before its .enc source; the source in the
// same pass is authoritative and replaces the stale output.
func TestDecryptAll_stale_ciphertext_output_with_valid_source_succeeds(t *testing.T) {
	identity := newIdentity(t)
	dir := t.TempDir()
	_, out := writeEncSource(t, dir, "app.env", []byte("FRESH=value\n"), identity.Recipient())
	stale, err := encryptArmored([]byte("STALE=value\n"), identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt stale output: %v", err)
	}
	if err := os.WriteFile(out, stale, 0o600); err != nil {
		t.Fatalf("write stale output: %v", err)
	}

	result, err := decryptAll(t.Context(), dir, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 1 || result.Failed != 0 {
		t.Fatalf("result = %+v, want Decrypted=1 and Failed=0", result)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "FRESH=value\n" {
		t.Errorf("output = %q, want fresh plaintext", got)
	}
}

// A static hardlink inside the root to ciphertext outside it must fail
// closed: the source link-count gate catches what symlink checks alone
// cannot, since a hardlink is a regular file.
func TestDecryptAll_source_with_multiple_links_outside_root_fails_closed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: hardlink behavior differs")
	}
	identity := newIdentity(t)
	base := t.TempDir()
	rootPath := filepath.Join(base, "root")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	plaintext := []byte("CROSS_ROOT=value\n")
	ciphertext, err := encryptArmored(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	outside := filepath.Join(base, "outside.env"+encSuffix)
	if err := os.WriteFile(outside, ciphertext, 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	inside := filepath.Join(rootPath, "import.env"+encSuffix)
	if err := os.Link(outside, inside); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}

	result, err := decryptAll(t.Context(), rootPath, []age.Identity{identity}, []string{".env"})
	if err != nil {
		t.Fatalf("decryptAll: %v", err)
	}
	if result.Decrypted != 0 || result.Failed != 1 {
		t.Errorf("result = %+v, want Decrypted=0 Failed=1", result)
	}
	assertNoOutput(t, filepath.Join(rootPath, "import.env"))
	assertSourcePreserved(t, outside, ciphertext)
	assertSourcePreserved(t, inside, ciphertext)
}
