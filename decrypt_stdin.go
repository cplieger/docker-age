package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// runDecryptStdin reads age-encrypted ciphertext from stdin, decrypts it
// using the provided identities, and writes the plaintext to stdout.
// Returns 0 on success, 1 on any failure.
func runDecryptStdin(identities []age.Identity) int {
	const maxInput = 10 << 20 // 10 MB
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxInput+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: read error: %v\n", err)
		return 1
	}
	if len(data) > maxInput {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: input exceeds %d bytes\n", maxInput)
		return 1
	}
	if len(data) == 0 {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: empty input\n")
		return 1
	}

	var reader io.Reader = bytes.NewReader(data)
	if bytes.HasPrefix(data, []byte(armoredHeader)) {
		reader = armor.NewReader(reader)
	} else if !bytes.HasPrefix(data, []byte(ageHeader)) {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: input is not age-encrypted\n")
		return 1
	}

	r, err := age.Decrypt(reader, identities...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: decrypt error: %v\n", err)
		return 1
	}

	const maxOutput = 1 << 20 // 1 MB
	cleartext, err := io.ReadAll(io.LimitReader(r, maxOutput+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: decrypt read error: %v\n", err)
		return 1
	}
	if len(cleartext) > maxOutput {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: decrypted output exceeds %d bytes\n", maxOutput)
		return 1
	}

	if _, err := os.Stdout.Write(cleartext); err != nil {
		fmt.Fprintf(os.Stderr, "decrypt-stdin: write error: %v\n", err)
		return 1
	}
	return 0
}
