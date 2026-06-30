package main

import (
	"bytes"
	"errors"
	"testing"

	"filippo.io/age"
)

// TestDecryptStream exercises the extracted pipe core directly: it reads from
// an in-memory reader and writes to an in-memory buffer, so the
// stdin/stdout-coupled path (previously 0% covered) is now testable. Each case
// asserts on the return code and on the bytes written to out; diagnostics go
// to slog and are deliberately not asserted on.
func TestDecryptStream(t *testing.T) {
	id := newIdentity(t)
	other := newIdentity(t)
	plaintext := []byte("KEY=value\n")

	armored, err := encryptArmored(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("encrypt armored: %v", err)
	}
	binary, err := encryptBinary(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("encrypt binary: %v", err)
	}
	wrongKey, err := encryptArmored(plaintext, other.Recipient())
	if err != nil {
		t.Fatalf("encrypt wrong key: %v", err)
	}
	// Plaintext one byte over the output cap: passes the input cap and
	// decrypts, then trips the maxDecryptedSize guard.
	oversizedOutput, err := encryptArmored(bytes.Repeat([]byte("A"), maxDecryptedSize+1), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt oversized output: %v", err)
	}
	// Age-headed bytes one over the input cap: trips the maxEncryptedSize
	// guard before any decrypt is attempted.
	oversizedInput := append([]byte(ageHeader), bytes.Repeat([]byte("X"), maxEncryptedSize+1)...)
	// Plaintext exactly at the output cap: the limit is inclusive, so this must
	// decrypt and be written back in full. The oversized-output case above
	// covers one byte over (rejected); pairing it with this exact-limit case
	// pins the boundary as inclusive rather than off-by-one.
	atCapPlaintext := bytes.Repeat([]byte("A"), maxDecryptedSize)
	atCapOutput, err := encryptArmored(atCapPlaintext, id.Recipient())
	if err != nil {
		t.Fatalf("encrypt at-cap output: %v", err)
	}

	tests := []struct {
		name     string
		input    []byte
		wantOut  []byte
		wantCode int
	}{
		{"armored round-trips", armored, plaintext, 0},
		{"binary round-trips", binary, plaintext, 0},
		{"empty input rejected", nil, nil, 1},
		{"non-age rejected", []byte("PLAIN=value\n"), nil, 1},
		{"wrong key fails", wrongKey, nil, 1},
		{"oversized input rejected", oversizedInput, nil, 1},
		{"oversized output rejected", oversizedOutput, nil, 1},
		{"output exactly at cap accepted", atCapOutput, atCapPlaintext, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := decryptStream(bytes.NewReader(tc.input), &out, []age.Identity{id})
			if code != tc.wantCode {
				t.Errorf("decryptStream code = %d, want %d", code, tc.wantCode)
			}
			if !bytes.Equal(out.Bytes(), tc.wantOut) {
				t.Errorf("decryptStream out = %q, want %q", out.Bytes(), tc.wantOut)
			}
		})
	}
}

// FuzzDecryptStream asserts the invariants that must hold for any input bytes:
// the return code is always 0 or 1; non-age input is always rejected with an
// empty output; and a failure (code 1) never writes anything to out.
func FuzzDecryptStream(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatalf("generate identity: %v", err)
	}
	armored, err := encryptArmored([]byte("KEY=val\n"), id.Recipient())
	if err != nil {
		f.Fatalf("encrypt armored: %v", err)
	}
	binary, err := encryptBinary([]byte("KEY=val\n"), id.Recipient())
	if err != nil {
		f.Fatalf("encrypt binary: %v", err)
	}
	f.Add(armored)
	f.Add(binary)
	f.Add([]byte{})
	f.Add([]byte("PLAIN=value\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		code := decryptStream(bytes.NewReader(data), &out, []age.Identity{id})
		if code != 0 && code != 1 {
			t.Fatalf("decryptStream code = %d, want 0 or 1", code)
		}
		isAge := bytes.HasPrefix(data, []byte(armoredHeader)) ||
			bytes.HasPrefix(data, []byte(ageHeader))
		if !isAge && code != 1 {
			t.Errorf("non-age input: code = %d, want 1", code)
		}
		if !isAge && out.Len() != 0 {
			t.Errorf("non-age input wrote %d bytes to out, want 0", out.Len())
		}
		if code == 1 && out.Len() != 0 {
			t.Errorf("failure (code 1) wrote %d bytes to out, want 0", out.Len())
		}
	})
}

// errReader always fails on Read, simulating a broken stdin pipe.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("simulated stdin read failure") }

// errWriter always fails on Write, simulating a broken stdout pipe -- the real
// failure mode behind `age-decrypt decrypt - | head -c N`, where the downstream
// consumer closes the pipe before all plaintext is written.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("simulated stdout write failure") }

// TestDecryptStream_read_error returns 1 when the input stream fails mid-read,
// before any decrypt is attempted. The bytes.Reader used by TestDecryptStream
// never errors, so the io.ReadAll error branch (decrypt_stdin.go:29-32) was
// previously unexercised. Mutating its `return 1` to `return 0` now fails here.
func TestDecryptStream_read_error(t *testing.T) {
	id := newIdentity(t)

	var out bytes.Buffer
	code := decryptStream(errReader{}, &out, []age.Identity{id})

	if code != 1 {
		t.Errorf("decryptStream(failing reader) = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("decryptStream(failing reader) wrote %d bytes to out, want 0", out.Len())
	}
}

// TestDecryptStream_write_error returns 1 when the plaintext decrypts cleanly
// but the output stream rejects the write (broken stdout pipe). Covers the
// out.Write error branch (decrypt_stdin.go:67-70), unreachable with the
// bytes.Buffer used by TestDecryptStream. Mutating its `return 1` to `return 0`
// now fails here.
func TestDecryptStream_write_error(t *testing.T) {
	id := newIdentity(t)
	ciphertext, err := encryptArmored([]byte("KEY=value\n"), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	code := decryptStream(bytes.NewReader(ciphertext), errWriter{}, []age.Identity{id})

	if code != 1 {
		t.Errorf("decryptStream(valid ciphertext, failing writer) = %d, want 1", code)
	}
}

// TestDecryptStream_rejects_corrupted_body feeds a binary ciphertext whose
// header is valid but whose final payload chunk is truncated by one byte:
// age.Decrypt parses the header successfully, then the body fails AEAD
// authentication on read. decryptStream must return 1 and write nothing -- a
// tampered body must never yield partial, unauthenticated plaintext. This
// reaches the io.ReadAll-after-Decrypt error branch (decrypt_stdin.go:58) that
// the wrong-key / header-corruption cases skip (they fail inside age.Decrypt).
func TestDecryptStream_rejects_corrupted_body(t *testing.T) {
	id := newIdentity(t)
	full, err := encryptBinary([]byte("KEY=value\n"), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	corrupt := full[:len(full)-1]

	var out bytes.Buffer
	code := decryptStream(bytes.NewReader(corrupt), &out, []age.Identity{id})

	if code != 1 {
		t.Errorf("decryptStream(corrupt body) = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("decryptStream(corrupt body) wrote %d bytes, want 0 (no unauthenticated plaintext)", out.Len())
	}
}
