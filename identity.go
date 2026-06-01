package main

import (
	"errors"
	"fmt"
	"os"

	"filippo.io/age"
)

// loadIdentity reads an age identity from the given file. The return type is
// the age.Identity interface rather than *age.X25519Identity so the caller
// survives future key-type changes (plugin, passphrase, etc.) without any
// downstream signature churn.
//
// It rejects files larger than 1 MB to prevent OOM on misconfigured mounts.
func loadIdentity(path string) (age.Identity, error) {
	// Path comes from the -key-file CLI flag (operator-supplied), not
	// from any untrusted input — gosec G304 is a false positive here.
	f, err := os.Open(path) // #nosec G304 -- CLI-flag-sourced trusted path
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Key files are tiny (a few hundred bytes). Reject anything over 1 MB
	// to prevent OOM if a large file is mounted by mistake.
	const maxKeyFileSize = 1 << 20
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if info.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("key file too large: %d bytes (max %d)", info.Size(), maxKeyFileSize)
	}

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	if len(identities) == 0 {
		return nil, errors.New("no identities found in key file")
	}
	return identities[0], nil
}
