package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
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

	// Tag every subsequent log line with the invocation mode.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)).With("mode", cfg.Mode))

	identities, err := loadIdentities(cfg.KeyFile)
	if err != nil {
		slog.Error("failed to load identities", "error", err)
		os.Exit(1)
	}

	slog.Info("configuration loaded", "repo_root", cfg.RepoRoot)

	if cfg.Mode == modeSubcommand {
		os.Exit(runSubcommand(cfg.RepoRoot, identities))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runServer(ctx, cfg.RepoRoot, health.DefaultPath, identities)
	stop()
	os.Exit(code)
}

// runSubcommand performs a single decrypt pass. Returns a non-zero exit
// code if any age-formatted file failed.
func runSubcommand(repoRoot string, identities []age.Identity) int {
	slog.Info("starting decrypt subcommand", "repo_root", repoRoot)
	result, err := decryptAll(context.Background(), repoRoot, identities)
	if err != nil {
		slog.Error("decryption failed", "error", err)
		return 1
	}
	logDecryptResult("decryption complete", result)
	warnIfNoFilesSeen(result, repoRoot)
	if result.Failed > 0 {
		slog.Warn("decryption completed with failures; some .env files remain ciphertext",
			"failed", result.Failed)
		return 1
	}
	return 0
}

// runServer performs a startup decrypt, sets the health marker according to
// the outcome, and waits for SIGINT/SIGTERM.
//
// A startup decrypt failure — a hard error (e.g. a stale or not-yet-cloned
// repo mount makes the root unreadable) or any per-file failure — marks the
// container UNHEALTHY but does NOT exit. The age container's role is to be a
// long-lived `docker exec age /age-decrypt decrypt` target for the deploy;
// exiting on a startup failure would crash-loop the container under
// `restart: unless-stopped` and remove the exec target precisely when the
// deploy needs it (the failure is typically a transient deploy-time mount
// race that a later exec or a container restart recovers from). The loud,
// deploy-blocking signal lives in runSubcommand, which still exits non-zero;
// server mode surfaces the problem through the health marker instead.
func runServer(ctx context.Context, repoRoot, markerPath string, identities []age.Identity) int {
	marker := health.NewMarker(markerPath)
	defer marker.Cleanup()
	marker.Set(false)

	result, err := decryptAll(ctx, repoRoot, identities)
	if err != nil {
		slog.Error("startup decryption failed; staying up and marking unhealthy", "error", err)
	} else {
		logDecryptResult("startup decryption complete", result)
		warnIfNoFilesSeen(result, repoRoot)
		if result.Failed > 0 {
			slog.Warn("startup decryption complete with failures; marking unhealthy",
				"failed", result.Failed)
		}
	}
	marker.Set(startupHealthy(result, err))

	slog.Info("ready, waiting for signals")
	<-ctx.Done()

	slog.Info("shutting down", "cause", context.Cause(ctx))
	return 0
}

// startupHealthy reports whether a startup decrypt result should mark the
// server healthy. Healthy requires both no hard error and zero per-file
// failures; any failure marks unhealthy. The container stays alive either
// way (see runServer).
func startupHealthy(result decryptResult, err error) bool {
	return err == nil && result.Failed == 0
}

// logDecryptResult emits a completion log line with the per-outcome
// counts from a decrypt pass under the given message.
func logDecryptResult(msg string, result decryptResult) {
	slog.Info(msg,
		"decrypted", result.Decrypted, "failed", result.Failed,
		"skipped", result.Skipped, "walk_errors", result.WalkErrors)
}

// warnIfNoFilesSeen emits the operator hint when a decrypt pass saw no
// .env files at all (decrypted, failed, and skipped all zero), which
// usually means a stale mount or a misconfigured AGE_REPO_ROOT.
func warnIfNoFilesSeen(result decryptResult, repoRoot string) {
	if result.Decrypted == 0 && result.Failed == 0 && result.Skipped == 0 {
		slog.Warn("no .env files found under repo root; check AGE_REPO_ROOT and that the repo mount is current",
			"repo_root", repoRoot)
	}
}
