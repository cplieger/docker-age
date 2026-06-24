package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// loadIdentities reads all age identities from the given file. The element
// type is the age.Identity interface rather than *age.X25519Identity so the
// caller survives future key-type changes (plugin, passphrase, etc.) without
// any downstream signature churn. All parsed identities are returned and
// forwarded to the variadic age.Decrypt so multi-identity key rotation
// (AGE_KEY_FILE documents "one identity per line") works as intended.
//
// It rejects files larger than 1 MB to prevent OOM on misconfigured mounts.
func loadIdentities(path string) ([]age.Identity, error) {
	// Path comes from the AGE_KEY_FILE environment variable
	// (operator-supplied, read in config.go), not from any untrusted
	// input — gosec G304 is a false positive here.
	f, err := os.Open(path) // #nosec G304 -- AGE_KEY_FILE env-sourced trusted path
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

	// Defence in depth: even if the size pre-check above is bypassed (e.g. a
	// mutated/removed guard), cap the read so an unbounded file can never reach
	// the parser. Mirrors the io.LimitReader bound used on every read in
	// decrypt.go; reads any file that passed the size check above.
	identities, err := age.ParseIdentities(io.LimitReader(f, maxKeyFileSize))
	if err != nil {
		// age's parse error can echo the raw key-file line (e.g.
		// "unknown identity type: %q"); drop it so a misconfigured key
		// file never leaks its contents into stderr/Loki.
		return nil, errors.New("parse key file: malformed identity " +
			"(contents omitted; AGE_KEY_FILE must be one age identity per line)")
	}
	if len(identities) == 0 {
		return nil, errors.New("no identities found in key file")
	}
	return identities, nil
}
