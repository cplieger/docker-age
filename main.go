package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"filippo.io/age"
)

func main() {
	// CLI health probe for Docker healthcheck (distroless has no curl/wget).
	if len(os.Args) > 1 && os.Args[1] == modeHealth {
		runProbe(healthMarkerPath)
	}

	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(2)
	}

	identity, err := loadIdentity(cfg.KeyFile)
	if err != nil {
		slog.Error("failed to load identity", "error", err)
		os.Exit(1)
	}

	// Tag every log line with the invocation mode.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)).With("mode", cfg.Mode))
	slog.Info("configuration loaded", "repo_root", cfg.RepoRoot)

	if cfg.Mode == "subcommand" {
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
	slog.Info("decryption complete",
		"decrypted", result.Decrypted, "failed", result.Failed)
	if result.Failed > 0 {
		return 1
	}
	return 0
}

// runServer performs a startup decrypt, marks healthy, and waits for
// SIGINT/SIGTERM.
func runServer(repoRoot string, identity age.Identity) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	marker := newHealthMarker(healthMarkerPath)
	marker.Set(false)

	result, err := decryptAll(ctx, repoRoot, identity)
	if err != nil {
		slog.Error("startup decryption failed", "error", err)
		return 1
	}
	slog.Info("startup decryption complete",
		"decrypted", result.Decrypted, "failed", result.Failed)

	marker.Set(true)
	defer marker.Cleanup()

	slog.Info("ready, waiting for signals")
	<-ctx.Done()

	slog.Info("shutting down", "cause", context.Cause(ctx))
	return 0
}
