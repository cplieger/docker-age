// Package main implements age-decrypt, which walks a mounted directory tree
// and decrypts age-encrypted files (binary or armored age format) in place.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cplieger/envx"
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
		case modeDecrypt:
			mode = modeDecrypt
			var err error
			extensions, targets, err = parseDecryptArgs(os.Args[2:])
			if err != nil {
				return config{}, err
			}
		case modeHealth:
			mode = modeHealth
		default:
			return config{}, fmt.Errorf("unknown subcommand %q (expected: health, decrypt)", os.Args[1])
		}
	}

	keyFile, err := envx.Require("AGE_KEY_FILE")
	if err != nil {
		return config{}, err
	}

	repoRoot := envx.String("AGE_REPO_ROOT", "/repo")

	return config{
		KeyFile:    keyFile,
		RepoRoot:   repoRoot,
		Mode:       mode,
		Extensions: extensions,
		Targets:    targets,
	}, nil
}

// parseDecryptArgs parses the arguments to the `decrypt` subcommand
// (os.Args[2:]): any number of --ext/--ext= suffix filters and positional
// targets, with a literal "--" ending flag parsing so the remaining args are
// treated as targets even if they start with "-". A bare "-" is a positional
// target (the stdin pipe sentinel), not a flag. It returns the collected
// extensions and targets, or an error for a malformed flag.
func parseDecryptArgs(args []string) (extensions, targets []string, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--ext":
			if i+1 >= len(args) {
				return nil, nil, errors.New("--ext requires a value (e.g. --ext .env)")
			}
			i++
			if extensions, err = appendNormalizedExt(extensions, args[i]); err != nil {
				return nil, nil, err
			}
		case strings.HasPrefix(arg, "--ext="):
			_, raw, _ := strings.Cut(arg, "=")
			if extensions, err = appendNormalizedExt(extensions, raw); err != nil {
				return nil, nil, err
			}
		case arg == "--":
			// Everything after "--" is a literal target.
			targets = append(targets, args[i+1:]...)
			return extensions, targets, nil
		case strings.HasPrefix(arg, "-") && arg != "-":
			return nil, nil, fmt.Errorf("unknown flag %q", arg)
		default:
			targets = append(targets, arg)
		}
	}
	return extensions, targets, nil
}

// appendNormalizedExt validates raw via normalizeExt and appends the result to
// extensions, returning the extended slice. It collapses the validate-then-
// append step shared by the "--ext value" and "--ext=value" flag forms.
func appendNormalizedExt(extensions []string, raw string) ([]string, error) {
	ext, err := normalizeExt(raw)
	if err != nil {
		return nil, err
	}
	return append(extensions, ext), nil
}

// normalizeExt validates a --ext value and ensures it carries a leading dot.
// An empty value is rejected so a malformed flag ("--ext=" or `--ext ""`)
// cannot silently collapse to the "." suffix, which matches almost nothing and
// turns the decrypt pass into a no-op that still exits 0 -- defeating the deploy
// gate that keys on the exit code.
func normalizeExt(raw string) (string, error) {
	if raw == "" || raw == "." {
		return "", errors.New("--ext requires a non-empty value (e.g. --ext .env)")
	}
	if !strings.HasPrefix(raw, ".") {
		raw = "." + raw
	}
	return raw, nil
}
