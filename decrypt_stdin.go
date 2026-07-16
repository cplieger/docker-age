package main

import (
	"context"
	"io"
	"log/slog"
	"os"

	"filippo.io/age"
)

// runDecryptStdin is the thin wrapper wired to the process standard streams:
// it reads age-encrypted ciphertext from stdin, decrypts it using the provided
// identities, and writes the plaintext to stdout. Returns 0 on success, 1 on
// any failure or cancellation.
func runDecryptStdin(ctx context.Context, identities []age.Identity) int {
	return decryptProcessStreams(ctx, os.Stdin, os.Stdout, identities)
}

// decryptProcessStreams makes blocking process I/O interruptible. It runs the
// pure decryptStream core in a goroutine and stops waiting the moment the
// context is canceled, so `decrypt -` exits promptly on SIGINT/SIGTERM
// regardless of which descriptor backs stdin/stdout.
//
// The closing helper below unblocks an in-flight read/write only on a POLLABLE
// descriptor (an os.Pipe, a socket). The std streams the real CLI inherits — a
// shell-redirected FIFO, a `docker exec -i` pipe — are plain BLOCKING
// descriptors the Go runtime never registers with its poller, so Close does
// NOT interrupt their in-flight syscall. Selecting on ctx.Done is what
// guarantees forward progress: run() returns 1 and main os.Exit's, reaping the
// (possibly still-blocked) goroutine. decryptStream keeps its own ctx checks at
// every publish boundary, so a canceled pass never reports success and never
// publishes after observing cancellation. The buffered result channel lets the
// goroutine send and exit even when no one is left to receive.
func decryptProcessStreams(ctx context.Context, in io.ReadCloser, out io.WriteCloser, identities []age.Identity) int {
	stopInterrupt := interruptStreamsOnCancel(ctx, in, out)
	defer stopInterrupt()

	result := make(chan int, 1)
	go func() { result <- decryptStream(ctx, in, out, identities) }()
	select {
	case code := <-result:
		return code
	case <-ctx.Done():
		slog.Error("decrypt-stdin canceled before completing", "error", ctx.Err())
		return 1
	}
}

func interruptStreamsOnCancel(ctx context.Context, streams ...io.Closer) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			for _, stream := range streams {
				_ = stream.Close()
			}
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func stdinCanceled(ctx context.Context) bool {
	if err := ctx.Err(); err != nil {
		slog.Error("decrypt-stdin canceled before completing", "error", err)
		return true
	}
	return false
}

// decryptStream reads age-encrypted ciphertext from in, decrypts it using the
// provided identities, and writes the plaintext to out. Diagnostics are
// emitted via slog. Returns 0 on success, 1 on any failure or cancellation. It
// is extracted from runDecryptStdin so the pipe path can be unit- and
// fuzz-tested without touching process globals, and enforces the same shared
// caps as the file path (maxEncryptedSize on input, maxDecryptedSize on output).
func decryptStream(ctx context.Context, in io.Reader, out io.Writer, identities []age.Identity) int {
	if stdinCanceled(ctx) {
		return 1
	}
	data, err := io.ReadAll(io.LimitReader(in, maxEncryptedSize+1))
	if stdinCanceled(ctx) {
		return 1
	}
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
	r, err := age.Decrypt(ageReader(format, data), identities...)
	if err != nil {
		slog.Error("decrypt-stdin decrypt error", "error", err)
		return 1
	}

	cleartext, err := io.ReadAll(io.LimitReader(r, maxDecryptedSize+1))
	defer clear(cleartext)
	if stdinCanceled(ctx) {
		return 1
	}
	if err != nil {
		slog.Error("decrypt-stdin decrypt read error", "error", err)
		return 1
	}
	if len(cleartext) > maxDecryptedSize {
		slog.Error("decrypt-stdin decrypted output exceeds size limit", "limit", maxDecryptedSize)
		return 1
	}

	n, err := out.Write(cleartext)
	if stdinCanceled(ctx) {
		return 1
	}
	if err != nil {
		slog.Error("decrypt-stdin write error", "error", err)
		return 1
	}
	if n != len(cleartext) {
		slog.Error("decrypt-stdin short write", "written", n, "expected", len(cleartext))
		return 1
	}
	return 0
}
