package main

import (
	"io"
	"log/slog"
	"os"

	"filippo.io/age"
)

// runDecryptStdin is the thin wrapper wired to the process standard streams:
// it reads age-encrypted ciphertext from stdin, decrypts it using the provided
// identities, and writes the plaintext to stdout. Returns 0 on success, 1 on
// any failure.
func runDecryptStdin(identities []age.Identity) int {
	return decryptStream(os.Stdin, os.Stdout, identities)
}

// decryptStream reads age-encrypted ciphertext from in, decrypts it using the
// provided identities, and writes the plaintext to out. Diagnostics are
// emitted via slog. Returns 0 on success, 1 on any failure. It is extracted
// from runDecryptStdin so the pipe path can be unit- and fuzz-tested without
// touching the process globals, and enforces the same shared caps as the file
// path (maxEncryptedSize on input, maxDecryptedSize on output).
func decryptStream(in io.Reader, out io.Writer, identities []age.Identity) int {
	data, err := io.ReadAll(io.LimitReader(in, maxEncryptedSize+1))
	if err != nil {
		slog.Error("decrypt-stdin read error", "error", err)
		return 1
	}
	if len(data) > maxEncryptedSize {
		slog.Error("decrypt-stdin input exceeds size limit", "limit", maxEncryptedSize)
		return 1
	}
	if len(data) == 0 {
		slog.Error("decrypt-stdin empty input")
		return 1
	}

	format := detectAgeFormat(data)
	if format == notAgeFormat {
		slog.Error("decrypt-stdin input is not age-encrypted")
		return 1
	}
	reader := ageReader(format, data)

	r, err := age.Decrypt(reader, identities...)
	if err != nil {
		slog.Error("decrypt-stdin decrypt error", "error", err)
		return 1
	}

	cleartext, err := io.ReadAll(io.LimitReader(r, maxDecryptedSize+1))
	defer clear(cleartext)
	if err != nil {
		slog.Error("decrypt-stdin decrypt read error", "error", err)
		return 1
	}
	if len(cleartext) > maxDecryptedSize {
		slog.Error("decrypt-stdin decrypted output exceeds size limit", "limit", maxDecryptedSize)
		return 1
	}

	if _, err := out.Write(cleartext); err != nil {
		slog.Error("decrypt-stdin write error", "error", err)
		return 1
	}
	return 0
}
