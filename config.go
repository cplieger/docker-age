package main

import (
	"errors"
	"fmt"
	"os"
)

type config struct {
	KeyFile  string
	RepoRoot string
	Mode     string
}

const modeHealth = "health"

func parseConfig() (config, error) {
	mode := "server"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "decrypt":
			mode = "subcommand"
		case modeHealth:
			// handled separately before parseConfig is called
			mode = modeHealth
		default:
			return config{}, fmt.Errorf("unknown subcommand %q (expected: health, decrypt)", os.Args[1])
		}
	}

	keyFile := os.Getenv("AGE_KEY_FILE")
	if keyFile == "" {
		return config{}, errors.New("AGE_KEY_FILE environment variable is required")
	}

	repoRoot := os.Getenv("AGE_REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "/repo"
	}

	return config{KeyFile: keyFile, RepoRoot: repoRoot, Mode: mode}, nil
}
