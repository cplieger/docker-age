package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// tmpCounter provides in-process uniqueness on top of the PID: even if two
// goroutines within the same process call decryptFile on the same rel at the
// same moment, they get distinct tmp paths. In typical deployments each
// age-decrypt invocation is its own OS process with its own PID, so PID
// alone would be enough — the counter just closes the door on future
// in-process callers.
var tmpCounter atomic.Uint64

const (
	ageHeader     = "age-encryption.org/v1"
	armoredHeader = "-----BEGIN AGE ENCRYPTED FILE-----"

	// tmpSuffix is the final path component of every decrypt temp file, named
	// <rel>.<pid>.<counter>.age-decrypt-tmp. The marker is specific to
	// age-decrypt, so the orphan sweep recognizes the tool's own temps by this
	// suffix alone (isOrphanTmpFile) and can never match — and therefore never
	// delete — a file the tool did not create, for any --ext.
	tmpSuffix = ".age-decrypt-tmp"
)

// Size caps shared by every decrypt path (the file walk in decryptFile and
// the stdin pipe in decryptStream). Both enforce the same documented
// contract: a 10 MB cap on encrypted input (reject oversized inputs to avoid
// OOM if a large file ends up with a matching suffix) and a 1 MB cap on
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
// (decryptFile) and the stdin pipe path (decryptStream) from drifting apart
// when a new age format is added.
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

// ageReader wraps already-buffered ciphertext in the reader age.Decrypt expects
// for the detected format: armor-decoded for armored, raw for binary.
func ageReader(format ageFormat, data []byte) io.Reader {
	var r io.Reader = bytes.NewReader(data)
	if format == armoredAgeFormat {
		r = armor.NewReader(r)
	}
	return r
}

// decryptResult summarizes a pass over the repo tree.
type decryptResult struct {
	Decrypted  int // age-formatted files that were successfully rewritten in place
	Failed     int // age-formatted files that failed to decrypt/write
	Skipped    int // non-age files encountered (legitimate skips)
	WalkErrors int // errors reported by the tree walk itself
}

// fileStatus reports the outcome of a single decryptFile call.
type fileStatus int

const (
	fileSkipped   fileStatus = iota // not an age-formatted file (legitimate skip)
	fileDecrypted                   // successfully decrypted and rewritten in place
	fileFailed                      // age-formatted but decrypt/write failed
)

// decryptFile reads, decrypts, and atomically overwrites a single file in place.
// Returns fileDecrypted on success, fileSkipped for non-age files, and
// fileFailed when an age-formatted file could not be rewritten.
func decryptFile(ctx context.Context, rootDir *os.Root, rel string, identities []age.Identity) fileStatus {
	if ctx.Err() != nil {
		slog.Debug("skipping file due to context cancellation", "file", rel, "error", ctx.Err())
		return fileSkipped
	}
	f, err := rootDir.Open(rel)
	if err != nil {
		slog.Warn("open error", "file", rel, "error", err)
		return fileFailed
	}
	defer func() { _ = f.Close() }()

	// Classify by the first bytes BEFORE reading the whole file. A non-age file
	// is a legitimate skip regardless of size (it was never a secret), so a
	// large non-age file (media, archive, log) in no-filter mode is recognised
	// from its header alone and never read in full. The armored banner is the
	// longer of the two headers, so it sets the peek length.
	header := make([]byte, len(armoredHeader))
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		slog.Warn("read error", "file", rel, "error", err)
		return fileFailed
	}
	header = header[:n]
	format := detectAgeFormat(header)
	if format == notAgeFormat {
		// Not an age file — legitimate skip, not a failure.
		slog.Debug("not age-encrypted, skipping", "file", rel)
		return fileSkipped
	}

	// Confirmed age-formatted: read the full ciphertext under the shared
	// maxEncryptedSize cap. The peeked header is replayed via MultiReader so the
	// bytes already consumed are not lost, and LimitReader bounds the total at
	// maxEncryptedSize+1. The cap guards only age input now — secret files are
	// small (a few KB); anything over 10 MB is rejected to prevent OOM on a
	// decompression bomb or runaway input.
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

	return writeDecryptedInPlace(rootDir, rel, cleartext)
}

// wipeTempFile removes the 0600 plaintext temp left by a failed write or rename.
// If removal fails for any reason other than the temp already being gone, it
// truncates the file to zero so decrypted plaintext cannot linger on disk until
// the age-bound orphan sweep reclaims it.
func wipeTempFile(rootDir *os.Root, tmpName string) {
	if rmErr := rootDir.Remove(tmpName); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		if tErr := rootDir.WriteFile(tmpName, nil, 0o600); tErr != nil {
			slog.Warn("temp cleanup error", "file", tmpName, "error", tErr)
		}
	}
}

// writeDecryptedInPlace atomically replaces rel with cleartext via a
// write-temp-then-rename. On a write or rename failure it removes the 0600
// plaintext temp, falling back to truncate-to-zero so plaintext cannot linger
// on disk. The temp name (<rel>.<pid>.<counter>.age-decrypt-tmp) isolates
// concurrent peers; the orphan reclaim path is isOrphanTmpFile/sweepOrphanTmpFile.
//
// When an orchestrator deploys many stacks in parallel, multiple age-decrypt
// invocations can run concurrently against the same tree. A shared tmp name
// makes concurrent peers race on the same path: one's rename vs another's
// orphan-sweep — observed in production as
//
//	renameat <dir>/.env.tmp <dir>/.env: no such file or directory
//
// Using the caller's PID plus a process-local atomic counter in the tmp name
// isolates every call so concurrent decrypt passes on the same tree — across
// processes or goroutines — cannot collide. The name always ends in tmpSuffix
// so the orphan sweep recognizes it by that marker alone.
func writeDecryptedInPlace(rootDir *os.Root, rel string, cleartext []byte) fileStatus {
	tmpName := fmt.Sprintf("%s.%d.%d%s", rel, os.Getpid(), tmpCounter.Add(1), tmpSuffix)
	if err := rootDir.WriteFile(tmpName, cleartext, 0o600); err != nil {
		// WriteFile creates+truncates the temp before writing, so a mid-write
		// failure (e.g. ENOSPC, I/O error) can leave partial decrypted plaintext
		// on disk. Mirror the rename-failure cleanup below: remove the temp, and
		// if removal fails, truncate to zero so plaintext cannot linger until the
		// orphan sweep reclaims it.
		wipeTempFile(rootDir, tmpName)
		slog.Warn("write error", "file", rel, "error", err)
		return fileFailed
	}
	if err := rootDir.Rename(tmpName, rel); err != nil {
		// Best-effort cleanup of the plaintext temp; log and continue. Each
		// tmp name is unique (PID + counter), so no later run reuses it -- a
		// leftover 0600 plaintext temp is reclaimed only by the age-bound
		// orphan sweep (see sweepOrphanTmpFile / isOrphanTmpFile). wipeTempFile
		// skips its truncate fallback when the temp is already gone (ErrNotExist)
		// so it never re-creates an empty orphan.
		wipeTempFile(rootDir, tmpName)
		slog.Warn("rename error", "file", rel, "tmp", tmpName, "error", err)
		return fileFailed
	}
	slog.Info("decrypted", "file", rel)
	return fileDecrypted
}

// sweepOrphanTmpFile removes a single orphaned decrypt temp file (a
// <rel>.<pid>.<counter>.age-decrypt-tmp left behind by a crashed or killed
// call) if it is older than staleThreshold. Young temp files are preserved to
// avoid ripping the tmp out from under a concurrent peer that is mid-decrypt.
func sweepOrphanTmpFile(rootDir *os.Root, rel string, staleThreshold time.Duration) bool {
	cutoff := time.Now().Add(-staleThreshold)
	info, statErr := rootDir.Stat(rel)
	if statErr != nil {
		return false
	}
	if info.ModTime().After(cutoff) {
		return false
	}
	if rmErr := rootDir.Remove(rel); rmErr != nil {
		if errors.Is(rmErr, fs.ErrNotExist) {
			return false // already swept by a concurrent peer
		}
		// Mirror wipeTempFile: if the stale 0600 plaintext temp cannot be unlinked
		// (e.g. an owned file under a non-writable parent dir), truncate it to zero
		// so decrypted plaintext cannot linger on disk. The staleThreshold check
		// above guarantees this is not a live peer's temp.
		if tErr := rootDir.WriteFile(rel, nil, 0o600); tErr != nil {
			slog.Warn("orphan tmp cleanup failed", "file", rel, "error", rmErr)
		}
		return false
	}
	slog.Info("removed orphan tmp file", "file", rel)
	return true
}

// isOrphanTmpFile reports whether name is a decrypt temp file left behind by a
// crashed or killed decryptFile call — it ends in tmpSuffix. Because the marker
// is age-decrypt-specific and always the final component of the temp name, this
// plain suffix match covers temps for ANY extension (so a `--ext .yaml` crash no
// longer leaks an unreclaimed plaintext orphan) while never matching a file the
// tool did not create.
func isOrphanTmpFile(name string) bool {
	return strings.HasSuffix(name, tmpSuffix)
}

// matchesAnyExt reports whether name ends in one of the given extensions. An
// empty extensions list matches every file (no --ext filter): every regular
// file is a decrypt candidate, skipped later by format detection if it is not
// age-formatted.
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

// decryptAll walks root, decrypting any age-encrypted files atomically in
// place. When extensions is non-empty, only files matching one of the given
// suffixes are considered; when empty, all regular files are candidates
// (skipped by format detection if not age-encrypted). It also sweeps
// orphaned decrypt temp files (any name ending in tmpSuffix) in the same pass.
// Returns per-outcome counts and an error only when the root itself cannot
// be opened.
func decryptAll(ctx context.Context, root string, identities []age.Identity, extensions []string) (decryptResult, error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		slog.Error("cannot open repo root", "root", root, "error", err)
		return decryptResult{}, fmt.Errorf("open root: %w", err)
	}
	defer func() { _ = rootDir.Close() }()

	const staleThreshold = 10 * time.Minute
	var result decryptResult
	var orphansRemoved int

	var rootWalkErr error
	canceled := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			canceled = true
			return filepath.SkipAll
		}
		if walkErr != nil {
			if path == root {
				slog.Error("repo root unreadable", "root", root, "error", walkErr)
				rootWalkErr = fmt.Errorf("walk root %s: %w", root, walkErr)
				return filepath.SkipAll
			}
			slog.Warn("walk error", "path", path, "error", walkErr)
			result.WalkErrors++
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		name := d.Name()

		// Handle orphan tmp files in the same walk.
		if isOrphanTmpFile(name) {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			if sweepOrphanTmpFile(rootDir, rel, staleThreshold) {
				orphansRemoved++
			}
			return nil
		}

		// Process files for decryption (extension filter or all).
		if !matchesAnyExt(name, extensions) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		switch decryptFile(ctx, rootDir, rel, identities) {
		case fileDecrypted:
			result.Decrypted++
		case fileFailed:
			result.Failed++
		case fileSkipped:
			result.Skipped++
		}
		return nil
	})

	if rootWalkErr != nil {
		return result, rootWalkErr
	}
	if canceled {
		slog.Error("decryption canceled before completing the tree", "root", root, "error", ctx.Err())
		return result, fmt.Errorf("decryption canceled: %w", ctx.Err())
	}
	slog.Debug("orphan tmp sweep complete", "removed", orphansRemoved)
	return result, nil
}
