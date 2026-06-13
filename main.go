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
	os.Exit(runServer(cfg.RepoRoot, identity))
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

// runServer performs a startup decrypt, marks healthy, and waits for
// SIGINT/SIGTERM.
func runServer(repoRoot string, identity age.Identity) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	marker := health.NewMarker(health.DefaultPath)
	defer marker.Cleanup()
	marker.Set(false)

	result, err := decryptAll(ctx, repoRoot, identity)
	if err != nil {
		slog.Error("startup decryption failed", "error", err)
		return 1
	}
	if result.Failed > 0 {
		slog.Warn("startup decryption complete with failures; marking unhealthy",
			"decrypted", result.Decrypted, "failed", result.Failed)
		marker.Set(false)
	} else {
		slog.Info("startup decryption complete",
			"decrypted", result.Decrypted, "failed", result.Failed)
		marker.Set(true)
	}

	slog.Info("ready, waiting for signals")
	<-ctx.Done()

	slog.Info("shutting down", "cause", context.Cause(ctx))
	return 0
}
