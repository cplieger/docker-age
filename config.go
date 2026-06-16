package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type config struct {
	KeyFile  string
	RepoRoot string
	Mode     string

	// Decrypt-specific options (populated only when Mode == modeDecrypt).
	Extensions []string // --ext filters (empty = all age-formatted files)
	Targets    []string // positional args; empty = walk RepoRoot; "-" = stdin/stdout pipe
}

const (
	modeHealth  = "health"
	modeServer  = "server"
	modeDecrypt = "decrypt"
)

func parseConfig() (config, error) {
	mode := modeServer
	var extensions []string
	var targets []string

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "decrypt":
			mode = modeDecrypt
			// Parse --ext flags and positional args from os.Args[2:]
			args := os.Args[2:]
			for i := 0; i < len(args); i++ {
				switch {
				case args[i] == "--ext":
					if i+1 >= len(args) {
						return config{}, errors.New("--ext requires a value (e.g. --ext .env)")
					}
					i++
					ext := args[i]
					if !strings.HasPrefix(ext, ".") {
						ext = "." + ext
					}
					extensions = append(extensions, ext)
				case strings.HasPrefix(args[i], "--ext="):
					_, ext, _ := strings.Cut(args[i], "=")
					if !strings.HasPrefix(ext, ".") {
						ext = "." + ext
					}
					extensions = append(extensions, ext)
				case args[i] == "--":
					targets = append(targets, args[i+1:]...)
					i = len(args) // break out of for loop
				case strings.HasPrefix(args[i], "-") && args[i] != "-":
					return config{}, fmt.Errorf("unknown flag %q", args[i])
				default:
					targets = append(targets, args[i])
				}
			}
		case modeHealth:
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

	return config{
		KeyFile:    keyFile,
		RepoRoot:   repoRoot,
		Mode:       mode,
		Extensions: extensions,
		Targets:    targets,
	}, nil
}
