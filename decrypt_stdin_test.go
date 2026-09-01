package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/cplieger/slogx/capture"
)

// TestDecryptStream exercises the extracted pipe core directly, reading from
// an in-memory reader and writing to an in-memory buffer. Each case asserts
// on the return code and the bytes written to out; diagnostics go to slog
// and are deliberately not asserted here.
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
	// Age-headed bytes one over the input cap: trips maxEncryptedSize before
	// any decrypt is attempted.
	oversizedInput := append([]byte(ageHeader), bytes.Repeat([]byte("X"), maxEncryptedSize+1)...)
	// Plaintext exactly at the output cap: the limit is inclusive, so this
	// must decrypt and be written back in full.
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
			code := decryptStream(t.Context(), bytes.NewReader(tc.input), &out, []age.Identity{id})
			if code != tc.wantCode {
				t.Errorf("decryptStream code = %d, want %d", code, tc.wantCode)
			}
			if !bytes.Equal(out.Bytes(), tc.wantOut) {
				t.Errorf("decryptStream out = %q, want %q", out.Bytes(), tc.wantOut)
			}
		})
	}
}

// The 10 MB encrypted-input cap is inclusive: an input of exactly that many
// bytes must reach the format check, and one byte more must be turned away
// for size before anything else is attempted. Both refusals exit 1, so the
// diagnostic is the only witness telling an operator which happened.
func TestDecryptStream_encrypted_input_cap_is_inclusive(t *testing.T) {
	id := newIdentity(t)
	tests := []struct {
		name    string
		size    int
		wantMsg string
	}{
		{name: "exactly at the cap", size: maxEncryptedSize, wantMsg: "decrypt-stdin input is not age-encrypted"},
		{name: "one byte over the cap", size: maxEncryptedSize + 1, wantMsg: "decrypt-stdin input exceeds size limit"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Not parallel: capture.Default swaps the global slog default.
			rec := capture.Default(t)
			var out bytes.Buffer

			code := decryptStream(t.Context(), bytes.NewReader(bytes.Repeat([]byte("X"), tc.size)), &out, []age.Identity{id})
			if code != 1 {
				t.Errorf("decryptStream(%d bytes) = %d, want 1", tc.size, code)
			}
			if out.Len() != 0 {
				t.Errorf("decryptStream(%d bytes) wrote %q, want nothing", tc.size, out.Bytes())
			}
			if got := rec.CountExact(tc.wantMsg); got != 1 {
				t.Errorf("decryptStream(%d bytes) logged %v, want exactly one %q", tc.size, rec.Messages(), tc.wantMsg)
			}
			if rec.Len() != 1 {
				t.Errorf("decryptStream(%d bytes) logged %d records (%v), want exactly one", tc.size, rec.Len(), rec.Messages())
			}
		})
	}
}

// FuzzDecryptStream asserts invariants that must hold for any input: the
// return code is always 0 or 1, non-age input is always rejected with an
// empty output, and a failure never writes anything to out.
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
		code := decryptStream(t.Context(), bytes.NewReader(data), &out, []age.Identity{id})
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

// errWriter always fails on Write, simulating a broken stdout pipe — the
// failure mode behind `age-decrypt decrypt - | head -c N`.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("simulated stdout write failure") }

// TestDecryptStream_read_error returns 1 when the input stream fails mid-read,
// before any decrypt is attempted (decrypt_stdin.go's io.ReadAll error branch,
// unexercised by TestDecryptStream's non-erroring bytes.Reader).
func TestDecryptStream_read_error(t *testing.T) {
	id := newIdentity(t)

	var out bytes.Buffer
	code := decryptStream(t.Context(), errReader{}, &out, []age.Identity{id})

	if code != 1 {
		t.Errorf("decryptStream(failing reader) = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("decryptStream(failing reader) wrote %d bytes to out, want 0", out.Len())
	}
}

// TestDecryptStream_write_error returns 1 when the plaintext decrypts cleanly
// but the output stream rejects the write (broken stdout pipe), covering the
// out.Write error branch that TestDecryptStream's bytes.Buffer never reaches.
func TestDecryptStream_write_error(t *testing.T) {
	id := newIdentity(t)
	ciphertext, err := encryptArmored([]byte("KEY=value\n"), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	code := decryptStream(t.Context(), bytes.NewReader(ciphertext), errWriter{}, []age.Identity{id})

	if code != 1 {
		t.Errorf("decryptStream(valid ciphertext, failing writer) = %d, want 1", code)
	}
}

// TestDecryptStream_rejects_corrupted_body feeds a binary ciphertext with a
// valid header but a payload truncated by one byte: AEAD authentication fails
// on read, and decryptStream must return 1 and write nothing.
func TestDecryptStream_rejects_corrupted_body(t *testing.T) {
	id := newIdentity(t)
	full, err := encryptBinary([]byte("KEY=value\n"), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	corrupt := full[:len(full)-1]

	var out bytes.Buffer
	code := decryptStream(t.Context(), bytes.NewReader(corrupt), &out, []age.Identity{id})

	if code != 1 {
		t.Errorf("decryptStream(corrupt body) = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("decryptStream(corrupt body) wrote %d bytes, want 0 (no unauthenticated plaintext)", out.Len())
	}
}

type cancelAtEOFReader struct {
	reader *bytes.Reader
	cancel context.CancelFunc
}

func (r *cancelAtEOFReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil {
		r.cancel()
	}
	return n, err
}

type signalingReadCloser struct {
	*os.File
	started chan struct{}
	once    sync.Once
}

func (r *signalingReadCloser) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.File.Read(p)
}

func TestDecryptStream_cancellation_writes_nothing(t *testing.T) {
	id := newIdentity(t)
	ciphertext, err := encryptArmored([]byte("KEY=value\n"), id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var out bytes.Buffer
		if code := decryptStream(ctx, bytes.NewReader(ciphertext), &out, []age.Identity{id}); code != 1 {
			t.Errorf("decryptStream(canceled) = %d, want 1", code)
		}
		if out.Len() != 0 {
			t.Errorf("canceled decrypt wrote %d bytes, want 0", out.Len())
		}
	})

	t.Run("canceled after input read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		reader := &cancelAtEOFReader{reader: bytes.NewReader(ciphertext), cancel: cancel}
		var out bytes.Buffer
		if code := decryptStream(ctx, reader, &out, []age.Identity{id}); code != 1 {
			t.Errorf("decryptStream(canceled after read) = %d, want 1", code)
		}
		if out.Len() != 0 {
			t.Errorf("canceled decrypt wrote %d bytes, want 0", out.Len())
		}
	})
}

func TestDecryptProcessStreams_cancellation_interrupts_blocked_input(t *testing.T) {
	id := newIdentity(t)
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = writeFile.Close() })
	in := &signalingReadCloser{File: readFile, started: make(chan struct{})}
	out, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("create output: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan int, 1)
	go func() {
		result <- decryptProcessStreams(ctx, in, out, []age.Identity{id})
	}()
	<-in.started
	cancel()

	select {
	case code := <-result:
		if code != 1 {
			t.Errorf("decryptProcessStreams(canceled) = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decryptProcessStreams did not interrupt its blocked stdin read")
	}
}

// unblockableReadCloser models a real inherited blocking descriptor (a
// shell-redirected FIFO, a `docker exec -i` pipe): its Read blocks until the
// test releases it, and its Close does NOT unblock an in-flight Read — the
// same limitation as a real os.File.Close on a descriptor the Go runtime
// never registered with its poller. The os.Pipe-based signalingReadCloser
// pins the pollable path where Close DOES unblock; this pins the path where
// only ctx.Done can rescue the process.
type unblockableReadCloser struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *unblockableReadCloser) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (r *unblockableReadCloser) Close() error { return nil }

// blackholeWriteCloser discards writes; the paired read never completes in the
// cancellation test below, so nothing is ever written to it.
type blackholeWriteCloser struct{}

func (blackholeWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (blackholeWriteCloser) Close() error                { return nil }

// TestDecryptProcessStreams_cancellation_returns_when_close_cannot_unblock is
// the regression guard for the inherited-blocking-descriptor liveness bug: on
// a descriptor whose Close cannot interrupt an in-flight Read, cancellation
// must still return promptly. Before the goroutine+select fix, the
// synchronous decryptStream call blocked here until the writer closed. The
// os.Pipe-based test above cannot catch this: os.Pipe fds are
// poller-registered, the one class where Close does unblock a read.
func TestDecryptProcessStreams_cancellation_returns_when_close_cannot_unblock(t *testing.T) {
	id := newIdentity(t)
	in := &unblockableReadCloser{started: make(chan struct{}), release: make(chan struct{})}
	// Release the blocked Read after the test so the decrypt goroutine — which
	// in production is reaped by os.Exit — does not leak past this test.
	t.Cleanup(func() { close(in.release) })

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan int, 1)
	go func() {
		result <- decryptProcessStreams(ctx, in, blackholeWriteCloser{}, []age.Identity{id})
	}()
	<-in.started
	cancel()

	select {
	case code := <-result:
		if code != 1 {
			t.Errorf("decryptProcessStreams(canceled, unblockable read) = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decryptProcessStreams did not return after cancellation when Close cannot unblock the read")
	}
}
