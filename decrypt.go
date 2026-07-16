package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	ageHeader     = "age-encryption.org/v1"
	armoredHeader = "-----BEGIN AGE ENCRYPTED FILE-----"

	// encSuffix marks a ciphertext source. `decrypt` only ever reads
	// `<name>.enc` files and writes the decrypted plaintext to the sibling
	// `<name>`; the source is never modified. The suffix is the contract that
	// keeps the ciphertext plane (tracked in git) and the plaintext plane
	// (generated, gitignored) apart.
	encSuffix = ".enc"

	// tmpSuffix terminates the reserved temp-file namespace. New v3 temps use
	// <output>.<32-lowercase-hex-chars>.age-decrypt-tmp; the orphan sweep also
	// recognizes the strict legacy <output>.<pid>.<counter> form so upgrades
	// can reclaim plaintext left by an interrupted v2 pass. The namespace is
	// deliberately strict: a generic suffix match could delete an unrelated
	// user file.
	tmpSuffix = ".age-decrypt-tmp"

	tempTokenBytes        = 16 // 128 bits; encoded as 32 lowercase hex chars
	maxTempCreateAttempts = 32
)

// Size caps shared by every decrypt path (the file walk in decryptFile and
// the stdin pipe in decryptStream). Both enforce the same documented
// contract: a 10 MB cap on encrypted input (reject oversized inputs to avoid
// OOM if a large file ends up with the .enc suffix) and a 1 MB cap on
// decrypted output (guard against decompression bombs). Declaring them once
// here keeps the two paths from silently diverging.
const (
	maxEncryptedSize = 10 << 20 // 10 MB cap on age ciphertext input
	maxDecryptedSize = 1 << 20  // 1 MB cap on decrypted plaintext output
)

// ageFormat classifies a file (or stdin payload) by its leading bytes:
// armored age, binary age, or not age-formatted at all.
type ageFormat int

const (
	notAgeFormat ageFormat = iota
	armoredAgeFormat
	binaryAgeFormat
)

// detectAgeFormat reports the age format of b by header prefix. Keeping the
// recognized headers in this single place stops the file-walk path
// (decryptFile), the stray-ciphertext sniff (sniffAgeFormat), and the stdin
// pipe path (decryptStream) from drifting apart when a new age format is
// added.
func detectAgeFormat(b []byte) ageFormat {
	switch {
	case bytes.HasPrefix(b, []byte(armoredHeader)):
		return armoredAgeFormat
	case bytes.HasPrefix(b, []byte(ageHeader)):
		return binaryAgeFormat
	default:
		return notAgeFormat
	}
}

// readHeader reads up to the longest recognized age header from r. Short
// reads (EOF on a file smaller than the armored banner) are not errors: the
// truncated prefix simply cannot match a header and classifies as notAgeFormat.
func readHeader(r io.Reader) ([]byte, error) {
	header := make([]byte, len(armoredHeader))
	n, err := io.ReadFull(r, header)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return header[:n], nil
}

// ageReader wraps already-buffered ciphertext in the reader age.Decrypt expects
// for the detected format: armor-decoded for armored, raw for binary.
func ageReader(format ageFormat, data []byte) io.Reader {
	var r io.Reader = bytes.NewReader(data)
	if format == armoredAgeFormat {
		r = armor.NewReader(r)
	}
	return r
}

// outputRelFor derives the plaintext output path for a .enc source: the same
// path minus the suffix. It rejects three names that cannot have a sane
// sibling. A non-.enc input is refused outright — defense in depth: every
// caller already filters on the suffix, and this guard makes it structurally
// impossible for a mis-routed call to derive an output equal to its source
// and overwrite ciphertext in place. A bare ".enc" has an empty output name.
// A double-suffixed "<x>.enc.enc" strips to "<x>.enc", which itself looks
// like a ciphertext source — the NEXT pass would classify the freshly written
// plaintext as a failed candidate, so it fails loudly now, when the misnamed
// file appears, instead of one pass later.
func outputRelFor(rel string) (string, error) {
	if !strings.HasSuffix(rel, encSuffix) {
		return "", fmt.Errorf("source %q does not end in %s", rel, encSuffix)
	}
	if filepath.Base(rel) == encSuffix {
		return "", fmt.Errorf("source %q has no output name (bare %s)", rel, encSuffix)
	}
	out := strings.TrimSuffix(rel, encSuffix)
	if strings.HasSuffix(out, encSuffix) {
		return "", fmt.Errorf("source %q strips to %q, which still ends in %s (rename the source)", rel, out, encSuffix)
	}
	return out, nil
}

// decryptResult summarizes a pass over the repo tree.
type decryptResult struct {
	Decrypted  int // .enc sources whose plaintext sibling was successfully written
	Failed     int // .enc sources that failed (non-age content, decrypt/write error) plus stray ciphertext found by the --ext guard
	Skipped    int // non-.enc files matching --ext that are already plaintext (the generated outputs on a re-run)
	WalkErrors int // errors reported by the tree walk itself
}

// fileStatus reports the outcome of a single decryptFile call.
type fileStatus int

const (
	fileSkipped   fileStatus = iota // not processed (context canceled)
	fileDecrypted                   // plaintext sibling successfully written
	fileFailed                      // source could not be decrypted to its sibling
)

func validateSingleLinkRegular(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (mode %s)", info.Mode())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("link count unavailable")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("link count is %d, want 1", stat.Nlink)
	}
	return nil
}

// openRegularReadOnly opens one path nonblocking and requires both Lstat
// snapshots and the opened descriptor to identify the same regular inode. This
// rejects final symlinks and closes the check/use gap that would otherwise let
// a regular file be swapped for a FIFO or device before the read.
func openRegularReadOnly(rootDir *os.Root, rel string) (*os.File, error) {
	before, err := rootDir.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if validationErr := validateSingleLinkRegular(before); validationErr != nil {
		return nil, fmt.Errorf("unsafe source %q before open: %w", rel, validationErr)
	}

	f, err := rootDir.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat opened source %q: %w", rel, err)
	}
	if validationErr := validateSingleLinkRegular(opened); validationErr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("unsafe opened source %q: %w", rel, validationErr)
	}
	after, err := rootDir.Lstat(rel)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("recheck opened source %q: %w", rel, err)
	}
	if validationErr := validateSingleLinkRegular(after); validationErr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("unsafe source %q after open: %w", rel, validationErr)
	}
	if !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		_ = f.Close()
		return nil, fmt.Errorf("source %q changed during open", rel)
	}
	return f, nil
}

// decryptFile reads one .enc ciphertext source and atomically writes its
// decrypted plaintext to the sibling output path (the source path minus
// .enc). The source is never modified. Returns fileDecrypted on success,
// fileFailed when the source is not valid age ciphertext or the sibling
// cannot be written, and fileSkipped only for a canceled context.
func decryptFile(ctx context.Context, rootDir *os.Root, rel string, identities []age.Identity) fileStatus {
	if ctx.Err() != nil {
		slog.Debug("skipping file due to context cancellation", "file", rel, "error", ctx.Err())
		return fileSkipped
	}
	outRel, err := outputRelFor(rel)
	if err != nil {
		slog.Warn("invalid source name", "file", rel, "error", err)
		return fileFailed
	}
	f, err := openRegularReadOnly(rootDir, rel)
	if err != nil {
		slog.Warn("open error", "file", rel, "error", err)
		return fileFailed
	}
	defer func() { _ = f.Close() }()

	// Classify by the first bytes BEFORE reading the whole file, so an
	// oversized non-age file is recognised from its header alone and never
	// read in full. Unlike v2's in-place walk (where any file might be a
	// legitimate plaintext), a .enc source that is NOT age ciphertext is a
	// broken workflow — encrypt-side error or corruption — and silently
	// copying it through would hide that, so it fails the pass.
	header, err := readHeader(f)
	if err != nil {
		slog.Warn("read error", "file", rel, "error", err)
		return fileFailed
	}
	format := detectAgeFormat(header)
	if format == notAgeFormat {
		slog.Warn("source is not age ciphertext (a .enc file must hold an age-encrypted payload)", "file", rel)
		return fileFailed
	}

	// Confirmed age-formatted: read the full ciphertext under the shared
	// maxEncryptedSize cap. The peeked header is replayed via MultiReader so the
	// bytes already consumed are not lost, and LimitReader bounds the total at
	// maxEncryptedSize+1. Secret files are small (a few KB); anything over
	// 10 MB is rejected to prevent OOM on a decompression bomb or runaway input.
	data, err := io.ReadAll(io.LimitReader(io.MultiReader(bytes.NewReader(header), f), int64(maxEncryptedSize+1)))
	if err != nil {
		slog.Warn("read error", "file", rel, "error", err)
		return fileFailed
	}
	if len(data) > maxEncryptedSize {
		slog.Warn("file exceeds max encrypted-input size, treating as failure", "file", rel, "size", len(data), "limit", maxEncryptedSize)
		return fileFailed
	}

	reader := ageReader(format, data)

	r, err := age.Decrypt(reader, identities...)
	if err != nil {
		slog.Warn("decrypt error", "file", rel, "error", err)
		return fileFailed
	}

	// Guard against decompression bombs via the shared maxDecryptedSize cap:
	// secret files should never exceed 1 MB.
	cleartext, err := io.ReadAll(io.LimitReader(r, maxDecryptedSize+1))
	defer clear(cleartext)
	if err != nil {
		slog.Warn("decrypt read error", "file", rel, "error", err)
		return fileFailed
	}
	if len(cleartext) > maxDecryptedSize {
		slog.Warn("decrypted file exceeds 1 MB limit, treating as failure", "file", rel)
		return fileFailed
	}

	return writeDecryptedSibling(ctx, rootDir, rel, outRel, cleartext)
}

// sniffAgeFormat opens rel just long enough to classify its leading bytes.
// It backs the stray-ciphertext guard: under --ext, a non-.enc file matching
// the filter is expected to be plaintext (a generated output or a committed
// plaintext config); age ciphertext there means an un-migrated or misnamed
// secret the pass cannot make available at its expected path.
func sniffAgeFormat(rootDir *os.Root, rel string) (ageFormat, error) {
	f, err := openRegularReadOnly(rootDir, rel)
	if err != nil {
		return notAgeFormat, err
	}
	defer func() { _ = f.Close() }()
	header, err := readHeader(f)
	if err != nil {
		return notAgeFormat, err
	}
	return detectAgeFormat(header), nil
}

// openExclusiveTemp creates a new 0600 file without following or truncating
// anything already present at tmpName. Keeping this primitive separate makes
// the pre-seeded regular-file, symlink, and hardlink cases directly testable.
func openExclusiveTemp(rootDir *os.Root, tmpName string) (*os.File, error) {
	return rootDir.OpenFile(tmpName,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}

// createTempFile picks a cryptographically random, same-directory name from
// the reserved v3 temp namespace. Randomness prevents another process that can
// observe the tree from predicting the next name; O_EXCL is the security
// boundary that refuses every pre-existing inode without touching it.
func createTempFile(rootDir *os.Root, outRel string) (string, *os.File, error) {
	var token [tempTokenBytes]byte
	for range maxTempCreateAttempts {
		if _, err := rand.Read(token[:]); err != nil {
			return "", nil, fmt.Errorf("generate temp name: %w", err)
		}
		tmpName := outRel + "." + hex.EncodeToString(token[:]) + tmpSuffix
		f, err := openExclusiveTemp(rootDir, tmpName)
		if err == nil {
			return tmpName, f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, fmt.Errorf("create temp %q: %w", tmpName, err)
		}
	}
	return "", nil, fmt.Errorf("create temp for %q: too many name collisions", outRel)
}

func writeAll(f *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := f.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// validateTempFile pins the properties required before a plaintext inode may
// be published or swept: regular, exactly 0600, and not hard-linked elsewhere.
func validateTempFile(info os.FileInfo) error {
	if err := validateSingleLinkRegular(info); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("mode is %04o, want 0600", perm)
	}
	return nil
}

func truncateAndCloseOwnedTemp(temp *os.File, expected os.FileInfo) (os.FileInfo, error) {
	var cleanupErrs []error
	if expected == nil {
		info, err := temp.Stat()
		if err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("stat owned temp: %w", err))
		} else {
			expected = info
		}
	}
	if err := temp.Truncate(0); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("truncate owned temp: %w", err))
	}
	if err := temp.Close(); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("close owned temp: %w", err))
	}
	return expected, errors.Join(cleanupErrs...)
}

func truncateOwnedTempPath(rootDir *os.Root, tmpName string, expected os.FileInfo) error {
	current, err := rootDir.Lstat(tmpName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lstat temp path: %w", err)
	}
	if expected == nil || !os.SameFile(expected, current) {
		return errors.New("temp path no longer names the owned inode")
	}

	f, err := rootDir.OpenFile(tmpName, os.O_WRONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("reopen owned temp: %w", err)
	}
	info, statErr := f.Stat()
	if statErr != nil {
		return errors.Join(fmt.Errorf("stat reopened temp: %w", statErr), f.Close())
	}
	if !os.SameFile(expected, info) {
		return errors.Join(errors.New("reopened temp is not the owned inode"), f.Close())
	}
	truncateErr := f.Truncate(0)
	closeErr := f.Close()
	if truncateErr != nil {
		truncateErr = fmt.Errorf("truncate reopened temp: %w", truncateErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close reopened temp: %w", closeErr)
	}
	return errors.Join(truncateErr, closeErr)
}

func removeOwnedTempPath(rootDir *os.Root, tmpName string, expected os.FileInfo) error {
	current, err := rootDir.Lstat(tmpName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("recheck temp path: %w", err)
	}
	if expected == nil || !os.SameFile(expected, current) {
		return errors.New("temp path changed during cleanup")
	}
	if err := rootDir.Remove(tmpName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove owned temp: %w", err)
	}
	return nil
}

// wipeOwnedTempFile zeroes the inode held by temp before removing its name.
// If the writer has already closed, it reopens the random path and requires
// the same inode before truncating. It never truncates by an unchecked path,
// so an attacker cannot swap in a symlink or hardlink victim during cleanup.
func wipeOwnedTempFile(rootDir *os.Root, tmpName string, temp *os.File, expected os.FileInfo) error {
	var cleanupErrs []error
	if temp != nil {
		var err error
		expected, err = truncateAndCloseOwnedTemp(temp, expected)
		cleanupErrs = append(cleanupErrs, err)
	}
	cleanupErrs = append(cleanupErrs,
		truncateOwnedTempPath(rootDir, tmpName, expected),
		removeOwnedTempPath(rootDir, tmpName, expected),
	)
	return errors.Join(cleanupErrs...)
}

// writeDecryptedSibling atomically publishes cleartext at outRel (the source
// path minus .enc) via an exclusively-created random temp in the same
// directory. Every byte is written through the owned descriptor, the inode is
// forced to mode 0600 and link count 1, and all write/sync/close errors are
// checked before the rename. The ciphertext source is never opened for write.
func writeDecryptedSibling(ctx context.Context, rootDir *os.Root, rel, outRel string, cleartext []byte) fileStatus {
	tmpName, temp, err := createTempFile(rootDir, outRel)
	if err != nil {
		slog.Warn("temp create error", "file", rel, "output", outRel, "error", err)
		return fileFailed
	}

	var expected os.FileInfo
	committed := false
	defer func() {
		if committed {
			return
		}
		if cleanupErr := wipeOwnedTempFile(rootDir, tmpName, temp, expected); cleanupErr != nil {
			slog.Warn("temp cleanup error", "file", tmpName, "error", cleanupErr)
		}
	}()

	if writeErr := writeAll(temp, cleartext); writeErr != nil {
		slog.Warn("write error", "file", rel, "output", outRel, "error", writeErr)
		return fileFailed
	}
	if chmodErr := temp.Chmod(0o600); chmodErr != nil {
		slog.Warn("temp chmod error", "file", rel, "output", outRel, "error", chmodErr)
		return fileFailed
	}
	if syncErr := temp.Sync(); syncErr != nil {
		slog.Warn("temp sync error", "file", rel, "output", outRel, "error", syncErr)
		return fileFailed
	}
	expected, err = temp.Stat()
	if err != nil {
		slog.Warn("temp stat error", "file", rel, "output", outRel, "error", err)
		return fileFailed
	}
	if validateErr := validateTempFile(expected); validateErr != nil {
		slog.Warn("unsafe temp file", "file", rel, "output", outRel, "error", validateErr)
		return fileFailed
	}
	if closeErr := temp.Close(); closeErr != nil {
		slog.Warn("temp close error", "file", rel, "output", outRel, "error", closeErr)
		return fileFailed
	}
	temp = nil

	// Recheck after close so a pre-rename path replacement or hardlink is
	// detected. The random name makes the remaining check-to-rename race
	// impractical under the documented stable-checkout deployment contract.
	if revalidateErr := revalidateTempBeforeRename(rootDir, tmpName, expected); revalidateErr != nil {
		slog.Warn("temp revalidation failed before rename", "file", rel, "output", outRel, "tmp", tmpName, "error", revalidateErr)
		return fileFailed
	}

	// A cancellation that landed after the entry check (during decrypt or temp
	// preparation) must not publish. Skipping the rename lets the deferred
	// cleanup wipe the owned temp and shrinks the post-cancellation publication
	// window to the single rename syscall below — the irreducible check-then-act
	// race, matching the stdin path. runDecrypt's post-loop ctx guard turns this
	// skip into the pass's non-zero exit.
	if ctx.Err() != nil {
		slog.Debug("canceled before publishing output", "file", rel, "output", outRel, "error", ctx.Err())
		return fileSkipped
	}
	if err := rootDir.Rename(tmpName, outRel); err != nil {
		slog.Warn("rename error", "file", rel, "output", outRel, "tmp", tmpName, "error", err)
		return fileFailed
	}
	committed = true
	slog.Info("decrypted", "file", rel, "output", outRel)
	return fileDecrypted
}

// revalidateTempBeforeRename re-checks, after the temp is closed, that tmpName
// still resolves to the same owned inode with a safe mode and single link, so a
// pre-rename path replacement or hardlink is caught before the publish. The
// random temp name makes the residual check-to-rename race impractical under
// the stable-checkout contract. The specific cause is returned (not logged) so
// the caller can attach its file/output/tmp fields in one place.
func revalidateTempBeforeRename(rootDir *os.Root, tmpName string, expected os.FileInfo) error {
	current, err := rootDir.Lstat(tmpName)
	if err != nil {
		return fmt.Errorf("temp path vanished: %w", err)
	}
	if !os.SameFile(expected, current) {
		return errors.New("temp path changed")
	}
	if err := validateTempFile(current); err != nil {
		return fmt.Errorf("unsafe temp file: %w", err)
	}
	return nil
}

// sweepOrphanTmpFile removes a stale temp only after opening it with
// O_NOFOLLOW and validating the strict namespace, regular-file mode, 0600
// permissions, and single link. If unlink fails, it truncates the validated
// descriptor—not the path—so a swapped symlink or hardlink cannot target an
// unrelated file.
func sweepOrphanTmpFile(rootDir *os.Root, rel string, staleThreshold time.Duration) bool {
	if !isOrphanTmpFile(filepath.Base(rel)) {
		return false
	}
	f, err := rootDir.OpenFile(rel, os.O_WRONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return false // renamed or swept by a concurrent pass
	}
	if err != nil {
		slog.Warn("orphan tmp inspection failed", "file", rel, "error", err)
		return false
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		slog.Warn("orphan tmp stat failed", "file", rel, "error", err)
		return false
	}
	if validateErr := validateTempFile(info); validateErr != nil {
		slog.Warn("refusing unsafe orphan tmp file", "file", rel, "error", validateErr)
		return false
	}
	if info.ModTime().After(time.Now().Add(-staleThreshold)) {
		return false
	}
	current, err := rootDir.Lstat(rel)
	if err != nil {
		return false
	}
	if !os.SameFile(info, current) {
		slog.Warn("orphan tmp path changed during inspection", "file", rel)
		return false
	}

	if err := rootDir.Remove(rel); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		if truncateErr := f.Truncate(0); truncateErr != nil {
			slog.Warn("orphan tmp cleanup failed", "file", rel,
				"remove_error", err, "truncate_error", truncateErr)
			return false
		}
		slog.Info("orphan tmp file truncated to zero (could not remove)",
			"file", rel, "remove_error", err)
		return false
	}
	slog.Info("removed orphan tmp file", "file", rel)
	return true
}

// isOrphanTmpFile recognizes only names this project has generated: the v3
// random-token grammar and the strict legacy PID/counter grammar. The final
// namespace is reserved; unrelated names that merely end in tmpSuffix are not
// touched.
func isOrphanTmpFile(name string) bool {
	stem, ok := strings.CutSuffix(filepath.Base(name), tmpSuffix)
	if !ok {
		return false
	}
	lastDot := strings.LastIndexByte(stem, '.')
	if lastDot <= 0 {
		return false
	}
	last := stem[lastDot+1:]
	if len(last) == tempTokenBytes*2 && isLowerHex(last) {
		return true
	}
	counterStem := stem[:lastDot]
	pidDot := strings.LastIndexByte(counterStem, '.')
	return pidDot > 0 && isPositiveDecimal(counterStem[pidDot+1:]) && isPositiveDecimal(last)
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return s != ""
}

func isPositiveDecimal(s string) bool {
	if s == "" {
		return false
	}
	nonzero := false
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
		nonzero = nonzero || r != '0'
	}
	return nonzero
}

// matchesAnyExt reports whether name ends in one of the given extensions. An
// empty extensions list matches every name (no --ext filter). For ciphertext
// candidates the caller passes the OUTPUT name (the source minus .enc), so
// `--ext .env` selects `app.env.enc` sources — the filter names the plaintext
// the deploy consumes, exactly as it did under the v2 in-place model.
func matchesAnyExt(name string, extensions []string) bool {
	if len(extensions) == 0 {
		return true
	}
	for _, ext := range extensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// decryptAll walks root, decrypting every matching .enc source to its
// plaintext sibling. When extensions is non-empty, a source is a candidate
// when its OUTPUT name (source minus .enc) matches one of the suffixes, and
// every non-.enc file matching a suffix is additionally sniffed for stray age
// ciphertext (an un-migrated secret at the plaintext path fails the pass
// rather than silently leaving ciphertext where the deploy reads). When
// extensions is empty, all .enc files are candidates and non-.enc files are
// ignored. It also sweeps stale orphaned decrypt temps in the strict random
// v3 or legacy PID/counter namespaces. Returns per-outcome counts and an error
// only when the root itself cannot be opened.
// treeWalk carries the mutable accounting for a single decryptAll pass so the
// per-entry visitor can be a named method (treeWalk.visit) rather than a
// deeply nested closure — the closure nesting was what pushed decryptAll's
// cognitive complexity past the ceiling even though each branch is simple.
//
// Pointer-bearing fields are grouped first to satisfy govet's fieldalignment
// (it keeps the GC pointer-scan range minimal); the layout is otherwise
// immaterial since decryptAll builds the value with keyed fields.
type treeWalk struct {
	ctx            context.Context
	rootWalkErr    error
	rootDir        *os.Root
	root           string
	identities     []age.Identity
	extensions     []string
	result         decryptResult
	staleThreshold time.Duration
	orphansRemoved int
	canceled       bool
}

func (w *treeWalk) visitCiphertext(rel string, d fs.DirEntry) {
	// Validate every .enc-shaped name BEFORE extension filtering. Otherwise
	// bare .enc and double .enc.enc sources can disappear behind --ext and
	// produce a clean zero-work exit.
	outRel, err := outputRelFor(rel)
	if err != nil {
		slog.Warn("invalid source name", "file", rel, "error", err)
		w.result.Failed++
		return
	}
	if !matchesAnyExt(filepath.Base(outRel), w.extensions) {
		return
	}
	if !d.Type().IsRegular() {
		slog.Warn("ciphertext source is not a regular file", "file", rel, "mode", d.Type())
		w.result.Failed++
		return
	}
	recordDecryptOutcome(&w.result, decryptFile(w.ctx, w.rootDir, rel, w.identities))
}

func (w *treeWalk) visitPlaintext(rel string, d fs.DirEntry) {
	// Non-.enc entries are out of scope without --ext. With a filter, every
	// matching path must be a regular plaintext file; symlinks, FIFOs, devices,
	// and directories fail closed rather than being silently skipped.
	if len(w.extensions) == 0 || !matchesAnyExt(d.Name(), w.extensions) {
		return
	}
	if !d.Type().IsRegular() {
		slog.Warn("plaintext path is not a regular file", "file", rel, "mode", d.Type())
		w.result.Failed++
		return
	}
	w.checkStray(rel)
}

// visit is the filepath.WalkDir callback for one tree entry: it honors context
// cancellation, records walk errors, reclaims orphaned decrypt temps, decrypts
// matching .enc candidates, and applies the stray-ciphertext guard to matching
// non-.enc files, folding every outcome into w.
func (w *treeWalk) visit(path string, d fs.DirEntry, walkErr error) error {
	if w.ctx.Err() != nil {
		w.canceled = true
		return filepath.SkipAll
	}
	if walkErr != nil {
		if recordWalkError(&w.result, w.root, path, walkErr) {
			w.rootWalkErr = fmt.Errorf("walk root %s: %w", w.root, walkErr)
			return filepath.SkipAll
		}
		return nil
	}
	rel, relErr := filepath.Rel(w.root, path)
	if relErr != nil {
		return nil
	}
	// The walk root itself is a container, not an entry selected by its name.
	if rel == "." && d.IsDir() {
		return nil
	}

	// Reclaim only names in the strict reserved temp namespace. The sweep does
	// its own no-follow regular/mode/link validation before touching an inode.
	if isOrphanTmpFile(d.Name()) {
		if sweepOrphanTmpFile(w.rootDir, rel, w.staleThreshold) {
			w.orphansRemoved++
		}
		return nil
	}

	if strings.HasSuffix(d.Name(), encSuffix) {
		w.visitCiphertext(rel, d)
		return nil
	}
	w.visitPlaintext(rel, d)
	return nil
}

// checkStray classifies a non-.enc file that matches the --ext filter. The
// deploy reads plaintext at exactly this path, so age ciphertext here is an
// un-migrated or misnamed secret: the pass cannot make its plaintext available
// (only .enc sources are decrypted), and proceeding would let the deploy read
// ciphertext. That is the same silent-no-op hazard the fatal root-walk error
// blocks, so it fails the pass loudly. A plaintext file is the expected state
// (a generated output from a previous pass, or a committed plaintext config)
// and counts as skipped; an unreadable file cannot be classified and fails
// closed.
func (w *treeWalk) checkStray(rel string) {
	// Lexical walks visit "x.env" before "x.env.enc". If a valid regular
	// sibling source exists, let that source's own decrypt result gate the pass
	// instead of first failing on stale ciphertext that the same pass replaces.
	// Lstat deliberately refuses a symlink source: non-regular candidates are
	// reported as failures by visit and must not suppress this guard.
	if info, err := w.rootDir.Lstat(rel + encSuffix); err == nil && info.Mode().IsRegular() {
		slog.Debug("plaintext path has a ciphertext sibling; source outcome will gate the pass", "file", rel)
		return
	}

	format, err := sniffAgeFormat(w.rootDir, rel)
	if err != nil {
		slog.Warn("cannot inspect file for stray ciphertext", "file", rel, "error", err)
		w.result.Failed++
		return
	}
	if format != notAgeFormat {
		slog.Error("stray age ciphertext at a plaintext path (rename to <name>"+encSuffix+" so it is decrypted)",
			"file", rel)
		w.result.Failed++
		return
	}
	slog.Debug("already plaintext, skipping", "file", rel)
	w.result.Skipped++
}

func decryptAll(ctx context.Context, root string, identities []age.Identity, extensions []string) (decryptResult, error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		slog.Error("cannot open repo root", "root", root, "error", err)
		return decryptResult{}, fmt.Errorf("open root: %w", err)
	}
	defer func() { _ = rootDir.Close() }()

	w := &treeWalk{
		ctx:            ctx,
		root:           root,
		rootDir:        rootDir,
		identities:     identities,
		extensions:     extensions,
		staleThreshold: 10 * time.Minute,
	}
	_ = filepath.WalkDir(root, w.visit)

	if w.rootWalkErr != nil {
		return w.result, w.rootWalkErr
	}
	if w.canceled {
		slog.Error("decryption canceled before completing the tree", "root", root, "error", ctx.Err())
		return w.result, fmt.Errorf("decryption canceled: %w", ctx.Err())
	}
	slog.Debug("orphan tmp sweep complete", "removed", w.orphansRemoved)
	return w.result, nil
}

// recordWalkError logs and accounts for an error reported by the tree walk.
// An error reading the root itself is fatal — the whole tree is unreadable
// (e.g. a stale mount), so it returns true to abort the pass. Any deeper
// per-entry error is logged, counted in WalkErrors, and tolerated (returns
// false) so a single unreadable subdir does not abort the rest of the walk.
func recordWalkError(result *decryptResult, root, path string, walkErr error) bool {
	if path == root {
		slog.Error("repo root unreadable", "root", root, "error", walkErr)
		return true
	}
	slog.Warn("walk error", "path", path, "error", walkErr)
	result.WalkErrors++
	return false
}

// recordDecryptOutcome folds a single decryptFile result into the running totals.
func recordDecryptOutcome(result *decryptResult, status fileStatus) {
	switch status {
	case fileDecrypted:
		result.Decrypted++
	case fileFailed:
		result.Failed++
	case fileSkipped:
		result.Skipped++
	}
}
