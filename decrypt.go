package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
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
)

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

// decryptFile reads, decrypts, and atomically overwrites a single .env file.
// Returns fileDecrypted on success, fileSkipped for non-age files, and
// fileFailed when an age-formatted file could not be rewritten.
func decryptFile(ctx context.Context, rootDir *os.Root, rel string, identities []age.Identity) fileStatus {
	if ctx.Err() != nil {
		slog.Debug("skipping file due to context cancellation", "file", rel, "error", ctx.Err())
		return fileSkipped
	}
	// Encrypted .env files are small (a few KB). Reject anything over 10 MB
	// to prevent OOM if a large file ends up with a .env suffix.
	const maxEncryptedSize = 10 << 20
	f, err := rootDir.Open(rel)
	if err != nil {
		slog.Warn("open error", "file", rel, "error", err)
		return fileFailed
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEncryptedSize+1))
	_ = f.Close()
	if err != nil {
		slog.Warn("read error", "file", rel, "error", err)
		return fileFailed
	}
	if len(data) > maxEncryptedSize {
		slog.Warn("encrypted file exceeds size limit, treating as failure", "file", rel, "size", len(data))
		return fileFailed
	}

	// Decide format once, then act — avoids re-scanning the prefix.
	isArmored := bytes.HasPrefix(data, []byte(armoredHeader))
	isBinary := bytes.HasPrefix(data, []byte(ageHeader))
	if !isArmored && !isBinary {
		// Not an age file — legitimate skip, not a failure.
		slog.Debug("not age-encrypted, skipping", "file", rel)
		return fileSkipped
	}

	var reader io.Reader = bytes.NewReader(data)
	if isArmored {
		reader = armor.NewReader(reader)
	}

	r, err := age.Decrypt(reader, identities...)
	if err != nil {
		slog.Warn("decrypt error", "file", rel, "error", err)
		return fileFailed
	}

	// Guard against decompression bombs: .env files should never exceed 1 MB.
	const maxDecryptedSize = 1 << 20
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

	// Atomic in-place rewrite: write to a sibling temp file, then rename.
	// When an orchestrator deploys many stacks in parallel, multiple
	// age-decrypt invocations can run concurrently against the same tree.
	// A single shared tmp name (e.g. ".env.tmp") makes concurrent peers
	// race on the same path: one's rename vs another's orphan-sweep —
	// observed in production as
	//   renameat <dir>/.env.tmp <dir>/.env: no such file or directory
	// Using the caller's PID plus a process-local atomic counter in the
	// tmp name isolates every call so concurrent decrypt passes on the
	// same tree — across processes or goroutines — cannot collide.
	tmpName := fmt.Sprintf("%s.tmp.%d.%d", rel, os.Getpid(), tmpCounter.Add(1))
	if err := rootDir.WriteFile(tmpName, cleartext, 0o600); err != nil {
		slog.Warn("write error", "file", rel, "error", err)
		return fileFailed
	}
	if err := rootDir.Rename(tmpName, rel); err != nil {
		// Best-effort cleanup of the temp file; log and continue even if
		// removal fails (the next run's temp write will overwrite it anyway).
		if rmErr := rootDir.Remove(tmpName); rmErr != nil {
			slog.Warn("temp cleanup error", "file", tmpName, "error", rmErr)
		}
		slog.Warn("rename error", "file", rel, "error", err)
		return fileFailed
	}
	slog.Info("decrypted", "file", rel)
	return fileDecrypted
}

// sweepOrphanTmpFile removes a single orphaned `.env.tmp` or
// `.env.tmp.<pid>.<counter>` file if it is older than staleThreshold.
// Young temp files are preserved to
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
		slog.Warn("orphan tmp cleanup failed", "file", rel, "error", rmErr)
		return false
	}
	slog.Info("removed orphan tmp file", "file", rel)
	return true
}

// orphanTmpRe matches the orphan tmp-file name shapes produced by decryptFile:
// the legacy bare ".env.tmp" and the PID-keyed ".env.tmp.<pid>.<counter>"
// (a non-empty run of digits and dots). The match is end-anchored, mirroring
// the original suffix-based check; a prefixed name (e.g. "app.env.tmp.9") still
// matches because only the tail is constrained.
var orphanTmpRe = regexp.MustCompile(`\.env\.tmp(\.[0-9.]+)?$`)

// isOrphanTmpFile reports whether the file name matches the orphan tmp pattern.
func isOrphanTmpFile(name string) bool {
	return orphanTmpRe.MatchString(name)
}

// decryptAll walks root, decrypting any age-encrypted files atomically in
// place. When extensions is non-empty, only files matching one of the given
// suffixes are considered; when empty, all regular files are candidates
// (skipped by format detection if not age-encrypted). It also sweeps
// orphaned .env.tmp files in the same pass.
// Returns per-outcome counts and an error only when the root itself cannot
// be opened.
func decryptAll(ctx context.Context, root string, identities []age.Identity, extensions []string) (decryptResult, error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return decryptResult{}, fmt.Errorf("open root: %w", err)
	}
	defer func() { _ = rootDir.Close() }()

	const staleThreshold = 10 * time.Minute
	var result decryptResult
	var orphansRemoved int

	var rootWalkErr error
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
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
		if len(extensions) > 0 {
			matched := false
			for _, ext := range extensions {
				if strings.HasSuffix(name, ext) {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
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
	slog.Debug("orphan tmp sweep complete", "removed", orphansRemoved)
	return result, nil
}
