package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

// TestDecryptAll_concurrent_safe reproduces a production race: when an
// orchestrator fans out pre_deploy across N stacks in parallel, N processes
// invoke "docker exec age /age-decrypt decrypt" simultaneously. With a
// shared ".env.tmp" name, one process's sweep deleted another's in-flight
// tmp, surfacing as:
//
//	renameat <dir>/.env.tmp <dir>/.env: no such file or directory
//
// This test simulates the fan-out in-process (each goroutine plays the role
// of a separate age-decrypt invocation) and asserts: all runs succeed, every
// .env file ends up with its correct plaintext, and no ".env.tmp*" debris
// is left on disk.
func TestDecryptAll_concurrent_safe(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	const numFiles = 15
	type envFile struct {
		path    string
		content []byte
	}
	files := make([]envFile, numFiles)
	for i := range numFiles {
		content := fmt.Appendf(nil, "KEY_%d=value_%d\n", i, i)
		p := writeEncryptedEnv(t, tmpDir, fmt.Sprintf("app%d.env", i), content, identity.Recipient())
		files[i] = envFile{path: p, content: content}
	}

	const concurrency = 8
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)
	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			// Each goroutine does its own full pass over the tree — same as
			// each stack's pre_deploy in the real topology.
			res, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity})
			if err != nil {
				errCh <- fmt.Errorf("decryptAll returned error: %w", err)
				return
			}
			if res.Failed != 0 {
				errCh <- fmt.Errorf("decryptAll reported %d failures (expected 0)", res.Failed)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}

	// Every file should now be decrypted to its original plaintext. The
	// first goroutine to race through a given file wins; idempotent re-reads
	// from the other goroutines are skipped (plaintext no longer has the
	// age header), which is the correct behaviour.
	for _, f := range files {
		got, err := os.ReadFile(f.path)
		if err != nil {
			t.Errorf("read %s: %v", f.path, err)
			continue
		}
		if !bytes.Equal(got, f.content) {
			t.Errorf("file %s: got %q, want %q", filepath.Base(f.path), got, f.content)
		}
	}

	// No leftover tmp debris in either legacy or per-PID form.
	_ = filepath.WalkDir(tmpDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == ".env.tmp" || (len(name) > len(".env.tmp.") && strings.Contains(name, ".env.tmp.")) {
			t.Errorf("unexpected tmp debris: %s", path)
		}
		return nil
	})
}

// TestDecryptAll_sweep_preserves_young_peer_tmps guards the age-bound sweep:
// a fresh per-PID tmp sitting on disk (another process's in-flight write)
// must not be removed. Removing it is exactly the bug that caused the
// original failure.
func TestDecryptAll_sweep_preserves_young_peer_tmps(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	// Simulate a peer process's live tmp, mtime = now (well within threshold).
	peerTmp := filepath.Join(tmpDir, "peer.env.tmp.12345")
	if err := os.WriteFile(peerTmp, []byte("mid-flight"), 0o600); err != nil {
		t.Fatalf("write peer tmp: %v", err)
	}

	if _, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}); err != nil {
		t.Fatalf("decryptAll: %v", err)
	}

	if _, err := os.Stat(peerTmp); err != nil {
		t.Fatalf("young peer tmp should be preserved, got stat err = %v", err)
	}
}

// TestDecryptAll_sweep_removes_stale_per_pid_tmps asserts that a sufficiently
// old per-PID tmp (from a long-dead run) does get cleaned up.
func TestDecryptAll_sweep_removes_stale_per_pid_tmps(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	staleTmp := filepath.Join(tmpDir, "abandoned.env.tmp.99999")
	if err := os.WriteFile(staleTmp, []byte("from a SIGKILLed run"), 0o600); err != nil {
		t.Fatalf("write stale tmp: %v", err)
	}
	// Backdate past the 10-minute threshold.
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(staleTmp, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if _, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}); err != nil {
		t.Fatalf("decryptAll: %v", err)
	}

	if _, err := os.Stat(staleTmp); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale tmp should have been removed, stat err = %v", err)
	}
}

// TestDecryptFile_tmp_name_encodes_pid pins the naming invariant the
// concurrency fix relies on: the tmp file name must be unique per caller
// (PID + in-process counter) so parallel age-decrypt invocations cannot
// collide on the same rename target.
func TestDecryptFile_tmp_name_encodes_pid(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("KEY=value\n")
	writeEncryptedEnv(t, tmpDir, "pinned.env", original, identity.Recipient())

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	if got := decryptFile(context.Background(), rootDir, "pinned.env", []age.Identity{identity}); got != fileDecrypted {
		t.Fatalf("decryptFile = %d, want %d (fileDecrypted)", got, fileDecrypted)
	}

	// After a successful rename, no matching per-caller tmp should linger.
	// Format: pinned.env.tmp.<pid>.<counter>
	prefix := fmt.Sprintf("pinned.env.tmp.%d.", os.Getpid())
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			t.Errorf("per-caller tmp %q should have been renamed away", e.Name())
		}
	}

	// And the final decrypted file must exist with the expected content.
	got, err := os.ReadFile(filepath.Join(tmpDir, "pinned.env"))
	if err != nil {
		t.Fatalf("read pinned.env: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("pinned.env content = %q, want %q", got, original)
	}
}

// TestIsOrphanTmpFile pins the boundaries of the orphan-tmp name
// matcher directly. Indirect coverage via the sweep tests only ever
// feeds valid orphan names, leaving the rejection branches (empty
// suffix, non-digit suffix) uncovered.
func TestIsOrphanTmpFile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "legacy bare suffix", input: ".env.tmp", want: true},
		{name: "legacy prefixed suffix", input: "app.env.tmp", want: true},
		{name: "per-pid single counter", input: "app.env.tmp.12345", want: true},
		{name: "per-pid pid dot counter", input: "app.env.tmp.12345.7", want: true},
		{name: "bare dotenv with pid", input: ".env.tmp.99999", want: true},
		{name: "plain env file not orphan", input: "app.env", want: false},
		{name: "decrypted dotenv not orphan", input: ".env", want: false},
		{name: "non env file", input: "config.txt", want: false},
		{name: "empty suffix after dot", input: "app.env.tmp.", want: false},
		{name: "non-digit suffix", input: "app.env.tmp.abc", want: false},
		{name: "mixed digit and letter suffix", input: "app.env.tmp.12a", want: false},
		{name: "envtmp without dot separator", input: ".env.tmpfoo", want: false},
		{name: "envtmp missing leading dot", input: "envtmp", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOrphanTmpFile(tc.input); got != tc.want {
				t.Errorf("isOrphanTmpFile(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
