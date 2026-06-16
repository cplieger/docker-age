package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"filippo.io/age"
	"github.com/cplieger/health"
)

func main() {
	// CLI health probe for Docker healthcheck (distroless has no curl/wget).
	if len(os.Args) > 1 && os.Args[1] == modeHealth {
		health.RunProbe(health.DefaultPath)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg, err := parseConfig()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)).With("mode", cfg.Mode))

	identities, err := loadIdentities(cfg.KeyFile)
	if err != nil {
		slog.Error("failed to load identities", "error", err)
		os.Exit(1)
	}

	if cfg.Mode == modeDecrypt {
		os.Exit(runDecrypt(&cfg, identities))
	}

	// Server mode (default, no subcommand): idle as PID 1, serve as a
	// long-lived `docker exec` target. No startup decrypt — all decryption
	// is triggered explicitly via exec.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runServer(ctx)
	stop()
	os.Exit(code)
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
func runDecrypt(cfg *config, identities []age.Identity) int {
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

	ctx := context.Background()
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
			}
			continue
		}
		result, err := decryptAll(ctx, root, identities, extensions)
		if err != nil {
			slog.Error("decryption failed", "root", root, "error", err)
			return 1
		}
		totalResult.Decrypted += result.Decrypted
		totalResult.Failed += result.Failed
		totalResult.Skipped += result.Skipped
		totalResult.WalkErrors += result.WalkErrors
	}

	logDecryptResult("decryption complete", totalResult)
	if len(cfg.Targets) == 0 {
		warnIfNoFilesSeen(totalResult, cfg.RepoRoot)
	}
	if totalResult.Failed > 0 {
		slog.Warn("decryption completed with failures", "failed", totalResult.Failed)
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

func warnIfNoFilesSeen(result decryptResult, repoRoot string) {
	if result.Decrypted == 0 && result.Failed == 0 && result.Skipped == 0 {
		slog.Warn("no matching files found under repo root; check AGE_REPO_ROOT and the mount",
			"repo_root", repoRoot)
	}
}
