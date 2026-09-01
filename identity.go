package main

import (
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

	identities, err := age.ParseIdentities(io.LimitReader(f, maxKeyFileSize))
	if err != nil {
		// age parse errors can expose a key line.
		return nil, errors.New("parse key file: malformed identity " +
			"(contents omitted; the IDENTITY_PATH file must hold one age identity per line)")
	}
	if len(identities) == 0 {
		return nil, errors.New("no identities found in key file")
	}
	return identities, nil
}
