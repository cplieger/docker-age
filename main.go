package main

import (
	"context"
	"fmt"
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

	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(2)
	}

	// Tag every log line with the invocation mode.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)).With("mode", cfg.Mode))

	identity, err := loadIdentity(cfg.KeyFile)
	if err != nil {
		slog.Error("failed to load identity", "error", err)
		os.Exit(1)
	}

	slog.Info("configuration loaded", "repo_root", cfg.RepoRoot)

	if cfg.Mode == modeSubcommand {
		os.Exit(runSubcommand(cfg.RepoRoot, identity))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runServer(ctx, cfg.RepoRoot, health.DefaultPath, identity)
	stop()
	os.Exit(code)
}

// runSubcommand performs a single decrypt pass. Returns a non-zero exit
// code if any age-formatted file failed.
func runSubcommand(repoRoot string, identity age.Identity) int {
	slog.Info("starting decrypt subcommand", "repo_root", repoRoot)
	result, err := decryptAll(context.Background(), repoRoot, identity)
	if err != nil {
		slog.Error("decryption failed", "error", err)
		return 1
	}
	if result.Failed > 0 {
		slog.Warn("decryption complete with failures",
			"decrypted", result.Decrypted, "failed", result.Failed)
		return 1
	}
	slog.Info("decryption complete",
		"decrypted", result.Decrypted, "failed", result.Failed)
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
func runServer(ctx context.Context, repoRoot, markerPath string, identity age.Identity) int {
	marker := health.NewMarker(markerPath)
	defer marker.Cleanup()
	marker.Set(false)

	result, err := decryptAll(ctx, repoRoot, identity)
	switch {
	case err != nil:
		slog.Error("startup decryption failed; staying up and marking unhealthy", "error", err)
	case result.Failed > 0:
		slog.Warn("startup decryption complete with failures; marking unhealthy",
			"decrypted", result.Decrypted, "failed", result.Failed)
	default:
		slog.Info("startup decryption complete",
			"decrypted", result.Decrypted, "failed", result.Failed)
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
