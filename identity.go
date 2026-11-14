package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// loadIdentities returns every identity in path for key rotation and bounds reads to 1 MB.
func loadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path) // #nosec G304 -- IDENTITY_PATH is operator configuration.
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	const maxKeyFileSize = 1 << 20
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if info.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("key file too large: %d bytes (max %d)", info.Size(), maxKeyFileSize)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize))
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if !hasContentLine(data) {
		return nil, errors.New("key file holds no age identity " +
			"(IDENTITY_PATH must hold one AGE-SECRET-KEY line)")
	}
	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		// age parse errors can expose a key line.
		return nil, errors.New("parse key file: malformed identity " +
			"(contents omitted; the IDENTITY_PATH file must hold one age identity per line)")
	}
	return identities, nil
}

// hasContentLine reports whether data holds a line that is neither blank nor an
// age comment, so an empty key file is told apart from a malformed one.
func hasContentLine(data []byte) bool {
	for line := range bytes.Lines(data) {
		if len(bytes.TrimSpace(line)) > 0 && !bytes.HasPrefix(line, []byte("#")) {
			return true
		}
	}
	return false
}
