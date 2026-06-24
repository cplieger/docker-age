package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
	"github.com/cplieger/health"
)

func main() {
	// CLI health probe for Docker healthcheck (distroless has no curl/wget).
	if len(os.Args) > 1 && os.Args[1] == modeHealth {
		health.RunProbe(health.DefaultPath)
	}

	level := logLevel()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	cfg, err := parseConfig()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})).With("mode", cfg.Mode))
	os.Exit(run(&cfg))
}

// run installs SIGINT/SIGTERM handling once and dispatches to the decrypt or
// server path, threading the signal-aware context into both. It is extracted
// from main so that `defer stop()` runs — a deferred call in main would be
// skipped by os.Exit.
func run(cfg *config) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Mode == modeDecrypt {
		identities, err := loadIdentities(cfg.KeyFile)
		if err != nil {
			slog.Error("failed to load identities", "error", err)
			return 1
		}
		return runDecrypt(ctx, cfg, identities)
	}

	// Server mode (default, no subcommand): idle as PID 1, serve as a
	// long-lived `docker exec` target. No key load here — the server never
	// decrypts; each `docker exec ... decrypt` loads its own identities.
	// Loading (and exiting on) the key in this idle path would crash-loop the
	// container under restart:unless-stopped and remove the exec target
	// precisely when an operator needs it. All decryption is triggered
	// explicitly via exec.
	return runServer(ctx)
}

// logLevel reads AGE_LOG_LEVEL (debug|info|warn|error, case-insensitive) and
// maps it to a slog.Level, defaulting to Info. An unset or unrecognized value
// keeps Info — the safe default for the deploy gate. Set AGE_LOG_LEVEL=debug to
// surface the per-file "not age-encrypted, skipping" and orphan-sweep lines
// when triaging why a pass decrypted nothing.
func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("AGE_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// runServer idles as PID 1 with a healthy marker, waiting for SIGINT/SIGTERM.
// All decrypt work happens via `docker exec` into this container.
func runServer(ctx context.Context) int {
	marker := health.NewMarker(health.DefaultPath)
	defer marker.Cleanup()
	marker.Set(true)

	slog.Info("ready, waiting for signals (decrypt via docker exec)")
	<-ctx.Done()

	slog.Info("shutting down", "cause", context.Cause(ctx))
	return 0
}

// runDecrypt handles all decrypt invocations:
//   - no targets AND no --ext: error (you must say what to decrypt)
//   - target "-": stdin/stdout pipe (single file, no disk I/O)
//   - target is a file: decrypt that one file in place
//   - target is a dir: walk that subtree (filtered by --ext if set)
//   - --ext with no targets: walk RepoRoot filtered by the given extensions
func runDecrypt(ctx context.Context, cfg *config, identities []age.Identity) int {
	// Pipe mode: stdin → decrypt → stdout
	if len(cfg.Targets) == 1 && cfg.Targets[0] == "-" {
		return runDecryptStdin(identities)
	}

	// Must specify what to decrypt.
	extensions := cfg.Extensions
	if len(extensions) == 0 && len(cfg.Targets) == 0 {
		slog.Error("decrypt requires at least one of: --ext, a target path, or '-' for stdin")
		return 1
	}

	// Determine walk roots
	roots := cfg.Targets
	if len(roots) == 0 {
		roots = []string{cfg.RepoRoot}
	}

	var totalResult decryptResult
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			slog.Error("target not accessible", "path", root, "error", err)
			return 1
		}
		if !info.IsDir() {
			status := decryptSingleFile(ctx, root, identities)
			switch status {
			case fileDecrypted:
				totalResult.Decrypted++
			case fileFailed:
				totalResult.Failed++
			case fileSkipped:
				totalResult.Skipped++
				if ctx.Err() == nil {
					slog.Info("named file is not age-encrypted, left unchanged", "path", root)
				}
			}
			continue
		}
		result, err := decryptAll(ctx, root, identities, extensions)
		if err != nil {
			// decryptAll already logged the precise cause at Error
			// ("cannot open repo root" or "repo root unreadable").
			return 1
		}
		totalResult.Decrypted += result.Decrypted
		totalResult.Failed += result.Failed
		totalResult.Skipped += result.Skipped
		totalResult.WalkErrors += result.WalkErrors
	}

	// A SIGINT/SIGTERM during the pass blocks the deploy: exit non-zero rather
	// than report success on a tree that was only partially processed. The walk
	// path surfaces cancellation as a decryptAll error (handled in the loop);
	// this catches a cancellation on the single-file path, where decryptFile
	// reports the interrupted file as skipped.
	if ctx.Err() != nil {
		slog.Error("decryption canceled before completing", "error", ctx.Err())
		return 1
	}

	logDecryptResult("decryption complete", totalResult)
	warnIfNoFilesSeen(totalResult, cfg.RepoRoot, cfg.Targets)
	// Deploy-blocking outcomes (non-zero exit): an age-formatted file that
	// failed to decrypt, OR a subtree the walk could not read. Both leave
	// ciphertext where plaintext was expected, so both must block the deploy
	// rather than let it proceed against unread secrets — the same fail-closed
	// stance the fatal root-level walk error takes, applied to a partial-tree
	// failure one level down. Log at Error so level=ERROR alerting pages,
	// matching the exit code's severity; the per-file and per-path messages
	// above stay Warn (degraded but continuing).
	if totalResult.Failed > 0 || totalResult.WalkErrors > 0 {
		slog.Error("decryption completed with failures",
			"failed", totalResult.Failed, "walk_errors", totalResult.WalkErrors)
		return 1
	}
	return 0
}

// decryptSingleFile decrypts one explicitly-named file in place.
func decryptSingleFile(ctx context.Context, path string, identities []age.Identity) fileStatus {
	dir := filepath.Dir(path)
	rootDir, err := os.OpenRoot(dir)
	if err != nil {
		slog.Error("cannot open parent dir", "path", path, "error", err)
		return fileFailed
	}
	defer func() { _ = rootDir.Close() }()
	return decryptFile(ctx, rootDir, filepath.Base(path), identities)
}

func logDecryptResult(msg string, result decryptResult) {
	slog.Info(msg,
		"decrypted", result.Decrypted, "failed", result.Failed,
		"skipped", result.Skipped, "walk_errors", result.WalkErrors)
}

func warnIfNoFilesSeen(result decryptResult, repoRoot string, targets []string) {
	if result.Decrypted != 0 || result.Failed != 0 || result.Skipped != 0 {
		return
	}
	if len(targets) == 0 {
		slog.Warn("no matching files found under repo root; check AGE_REPO_ROOT and the mount",
			"repo_root", repoRoot)
		return
	}
	slog.Warn("no matching files found under the named target(s); check the path and --ext",
		"targets", targets)
}
