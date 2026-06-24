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
// shared tmp name, one process's sweep deleted another's in-flight tmp,
// surfacing as:
//
//	renameat <dir>/.env.tmp <dir>/.env: no such file or directory
//
// This test simulates the fan-out in-process (each goroutine plays the role
// of a separate age-decrypt invocation) and asserts: all runs succeed, every
// .env file ends up with its correct plaintext, and no decrypt-temp debris
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
			res, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil)
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

	// No leftover decrypt-temp debris (any name carrying the tmpSuffix marker).
	_ = filepath.WalkDir(tmpDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if isOrphanTmpFile(d.Name()) {
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
	peerTmp := filepath.Join(tmpDir, "peer.env.12345.1"+tmpSuffix)
	if err := os.WriteFile(peerTmp, []byte("mid-flight"), 0o600); err != nil {
		t.Fatalf("write peer tmp: %v", err)
	}

	if _, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil); err != nil {
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

	staleTmp := filepath.Join(tmpDir, "abandoned.env.99999.1"+tmpSuffix)
	if err := os.WriteFile(staleTmp, []byte("from a SIGKILLed run"), 0o600); err != nil {
		t.Fatalf("write stale tmp: %v", err)
	}
	// Backdate past the 10-minute threshold.
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(staleTmp, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if _, err := decryptAll(context.Background(), tmpDir, []age.Identity{identity}, nil); err != nil {
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

	// After a successful rename, no decrypt temp should linger. The temp is
	// named <rel>.<pid>.<counter>.age-decrypt-tmp; assert none carrying this
	// caller's PID and the marker remains.
	pidMark := fmt.Sprintf("pinned.env.%d.", os.Getpid())
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), pidMark) && strings.HasSuffix(e.Name(), tmpSuffix) {
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

// TestIsOrphanTmpFile pins the decrypt-temp matcher: it recognizes a file by
// the age-decrypt-tmp marker alone, regardless of the underlying extension
// (the v2 coverage fix), and deliberately no longer matches the legacy
// ".env.tmp" shapes — temps are migrated to the marker, not kept compatible.
func TestIsOrphanTmpFile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "env temp", input: "app.env.12345.7" + tmpSuffix, want: true},
		{name: "bare dotenv temp", input: ".env.99999.1" + tmpSuffix, want: true},
		{name: "non-env temp (the v2 coverage gap)", input: "config.yaml.4242.2" + tmpSuffix, want: true},
		{name: "json temp", input: "secrets.json.1.1" + tmpSuffix, want: true},
		{name: "marker alone", input: tmpSuffix, want: true},
		{name: "plain env file", input: "app.env", want: false},
		{name: "decrypted dotenv", input: ".env", want: false},
		{name: "non env file", input: "config.txt", want: false},
		{name: "legacy bare suffix no longer matched", input: ".env.tmp", want: false},
		{name: "legacy pid-keyed suffix no longer matched", input: "app.env.tmp.12345.7", want: false},
		{name: "marker not at end", input: "note" + tmpSuffix + ".bak", want: false},
		{name: "marker substring missing leading dot", input: "fileage-decrypt-tmp", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOrphanTmpFile(tc.input); got != tc.want {
				t.Errorf("isOrphanTmpFile(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
