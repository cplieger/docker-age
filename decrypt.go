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
	Decrypted int // age-formatted files that were successfully rewritten in place
	Failed    int // age-formatted files that failed to decrypt/write
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
func decryptFile(ctx context.Context, rootDir *os.Root, rel string, identity age.Identity) fileStatus {
	if ctx.Err() != nil {
		return fileFailed
	}
	// Encrypted .env files are small (a few KB). Reject anything over 10 MB
	// to prevent OOM if a large file ends up with a .env suffix.
	const maxEncryptedSize = 10 << 20
	info, err := rootDir.Stat(rel)
	if err != nil {
		slog.Warn("stat error", "file", rel, "error", err)
		return fileFailed
	}
	if info.Size() > maxEncryptedSize {
		slog.Warn("encrypted file too large, skipping", "file", rel, "size", info.Size())
		return fileFailed
	}

	data, err := rootDir.ReadFile(rel)
	if err != nil {
		slog.Warn("read error", "file", rel, "error", err)
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

	r, err := age.Decrypt(reader, identity)
	if err != nil {
		slog.Warn("decrypt error", "file", rel, "error", err)
		return fileFailed
	}

	// Guard against decompression bombs: .env files should never exceed 1 MB.
	const maxDecryptedSize = 1 << 20
	cleartext, err := io.ReadAll(io.LimitReader(r, maxDecryptedSize+1))
	if err != nil {
		slog.Warn("decrypt read error", "file", rel, "error", err)
		return fileFailed
	}
	if len(cleartext) > maxDecryptedSize {
		slog.Warn("decrypted file exceeds 1 MB limit, skipping", "file", rel)
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

// sweepOrphanTmpFile removes a single orphaned `.env.tmp` or `.env.tmp.<pid>`
// file if it is older than staleThreshold. Young temp files are preserved to
// avoid ripping the tmp out from under a concurrent peer that is mid-decrypt.
func sweepOrphanTmpFile(rootDir *os.Root, rel string, staleThreshold time.Duration) {
	cutoff := time.Now().Add(-staleThreshold)
	info, statErr := rootDir.Stat(rel)
	if statErr != nil {
		return
	}
	if info.ModTime().After(cutoff) {
		return
	}
	if rmErr := rootDir.Remove(rel); rmErr != nil {
		slog.Warn("orphan tmp cleanup failed", "file", rel, "error", rmErr)
		return
	}
	slog.Info("removed orphan tmp file", "file", rel)
}

// isOrphanTmpFile reports whether the file name matches the orphan tmp pattern.
func isOrphanTmpFile(name string) bool {
	return strings.HasSuffix(name, ".env.tmp") || strings.Contains(name, ".env.tmp.")
}

// decryptAll walks root for .env files, decrypting any age-encrypted ones
// atomically in place. It also sweeps orphaned .env.tmp files in the same
// pass, eliminating a redundant full tree traversal.
// Returns per-outcome counts and an error only when the root itself cannot
// be opened.
func decryptAll(ctx context.Context, root string, identity age.Identity) (decryptResult, error) {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return decryptResult{}, fmt.Errorf("open root: %w", err)
	}
	defer func() { _ = rootDir.Close() }()

	const staleThreshold = 10 * time.Minute
	var result decryptResult
	var orphansRemoved int

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if walkErr != nil {
			slog.Warn("walk error", "path", path, "error", walkErr)
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
			sweepOrphanTmpFile(rootDir, rel, staleThreshold)
			orphansRemoved++
			return nil
		}

		// Process .env files for decryption.
		if !strings.HasSuffix(path, ".env") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		switch decryptFile(ctx, rootDir, rel, identity) {
		case fileDecrypted:
			result.Decrypted++
		case fileFailed:
			result.Failed++
		}
		return nil
	})

	slog.Debug("orphan tmp sweep complete", "removed", orphansRemoved)
	return result, nil
}
