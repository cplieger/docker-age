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
			code := decryptStream(context.Background(), bytes.NewReader(tc.input), &out, []age.Identity{id})
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
		code := decryptStream(context.Background(), bytes.NewReader(data), &out, []age.Identity{id})
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
	code := decryptStream(context.Background(), errReader{}, &out, []age.Identity{id})

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

	code := decryptStream(context.Background(), bytes.NewReader(ciphertext), errWriter{}, []age.Identity{id})

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
	code := decryptStream(context.Background(), bytes.NewReader(corrupt), &out, []age.Identity{id})

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
		ctx, cancel := context.WithCancel(context.Background())
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

	ctx, cancel := context.WithCancel(context.Background())
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

// unblockableReadCloser models a real inherited BLOCKING descriptor (a
// shell-redirected FIFO, a `docker exec -i` pipe): its Read blocks until the
// test releases it, and — crucially — its Close does NOT unblock an in-flight
// Read. That is exactly how os.File.Close behaves on a descriptor the Go
// runtime never registered with its poller: it cannot interrupt the syscall.
// The os.Pipe-based signalingReadCloser pins the pollable path where Close DOES
// unblock; this pins the path where only ctx.Done can rescue the process.
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
// the regression guard for the inherited-blocking-descriptor liveness bug. On a
// descriptor whose Close does NOT interrupt an in-flight Read — the descriptors
// `decrypt -` actually runs against — cancellation must still return promptly.
// Before the goroutine+select fix, the synchronous decryptStream call blocked
// here forever and the process survived SIGINT/SIGTERM until the writer closed
// (signal.NotifyContext had already consumed the signal). The os.Pipe-based
// test above cannot catch this: os.Pipe fds are poller-registered, the one
// class where Close does unblock a read.
func TestDecryptProcessStreams_cancellation_returns_when_close_cannot_unblock(t *testing.T) {
	id := newIdentity(t)
	in := &unblockableReadCloser{started: make(chan struct{}), release: make(chan struct{})}
	// Release the blocked Read after the test so the decrypt goroutine — which
	// in production is reaped by os.Exit — does not leak past this test.
	t.Cleanup(func() { close(in.release) })

	ctx, cancel := context.WithCancel(context.Background())
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
