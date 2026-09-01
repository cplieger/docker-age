package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

// TestDecryptAll_concurrent_safe reproduces the production race the tmp-name
// scheme guards: when an orchestrator fans out pre_deploy across N stacks in
// parallel, N processes invoke the decrypt pass simultaneously. Every pass
// re-decrypts each source to its sibling, so concurrent passes all write the
// same outputs — atomically, last writer wins with identical content.
func TestDecryptAll_concurrent_safe(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	const numFiles = 15
	type envFile struct {
		src     string
		out     string
		content []byte
	}
	files := make([]envFile, numFiles)
	for i := range numFiles {
		content := fmt.Appendf(nil, "KEY_%d=value_%d\n", i, i)
		src, out := writeEncSource(t, tmpDir, fmt.Sprintf("app%d.env", i), content, identity.Recipient())
		files[i] = envFile{src: src, out: out, content: content}
	}

	const concurrency = 8
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)
	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			res, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, []string{".env"})
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

	// Every output holds its plaintext; every source is still ciphertext.
	for _, f := range files {
		got, err := os.ReadFile(f.out)
		if err != nil {
			t.Errorf("read %s: %v", f.out, err)
			continue
		}
		if !bytes.Equal(got, f.content) {
			t.Errorf("output %s: got %q, want %q", filepath.Base(f.out), got, f.content)
		}
		srcData, err := os.ReadFile(f.src)
		if err != nil {
			t.Errorf("read source %s: %v", f.src, err)
			continue
		}
		if !bytes.HasPrefix(srcData, []byte(armoredHeader)) {
			t.Errorf("source %s lost its ciphertext", filepath.Base(f.src))
		}
	}

	// No leftover decrypt-temp debris.
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
// a fresh temp in the recognized namespace, simulating another process's
// in-flight write, must not be removed.
func TestDecryptAll_sweep_preserves_young_peer_tmps(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	peerTmp := filepath.Join(tmpDir, "peer.env.12345.1"+tmpSuffix)
	if err := os.WriteFile(peerTmp, []byte("mid-flight"), 0o600); err != nil {
		t.Fatalf("write peer tmp: %v", err)
	}

	if _, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil); err != nil {
		t.Fatalf("decryptAll: %v", err)
	}

	if _, err := os.Stat(peerTmp); err != nil {
		t.Fatalf("young peer tmp should be preserved, got stat err = %v", err)
	}
}

// TestDecryptAll_sweep_removes_stale_per_pid_tmps asserts upgrade
// compatibility: a sufficiently old legacy PID/counter temp is cleaned up.
func TestDecryptAll_sweep_removes_stale_per_pid_tmps(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	staleTmp := filepath.Join(tmpDir, "abandoned.env.99999.1"+tmpSuffix)
	if err := os.WriteFile(staleTmp, []byte("from a SIGKILLed run"), 0o600); err != nil {
		t.Fatalf("write stale tmp: %v", err)
	}
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(staleTmp, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if _, err := decryptAll(t.Context(), tmpDir, []age.Identity{identity}, nil); err != nil {
		t.Fatalf("decryptAll: %v", err)
	}

	if _, err := os.Stat(staleTmp); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale tmp should have been removed, stat err = %v", err)
	}
}

// TestDecryptFile_random_tmp_is_reclaimed pins the observable naming
// invariant: successful decrypt leaves no strict random-token temp behind.
func TestDecryptFile_random_tmp_is_reclaimed(t *testing.T) {
	identity := newIdentity(t)
	tmpDir := t.TempDir()

	original := []byte("KEY=value\n")
	src, out := writeEncSource(t, tmpDir, "pinned.env", original, identity.Recipient())

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	if got := decryptFile(t.Context(), rootDir, "pinned.env"+encSuffix, []age.Identity{identity}); got != fileDecrypted {
		t.Fatalf("decryptFile = %d, want %d (fileDecrypted)", got, fileDecrypted)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if isOrphanTmpFile(e.Name()) {
			t.Errorf("decrypt temp %q should have been renamed away", e.Name())
		}
	}

	// The output holds the plaintext and the source survives as ciphertext.
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("output content = %q, want %q", got, original)
	}
	srcData, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !bytes.HasPrefix(srcData, []byte(armoredHeader)) {
		t.Error("source lost its ciphertext")
	}
}

// TestIsOrphanTmpFile pins the reserved namespace: random-token names and
// strict legacy PID/counter names match; a generic marker suffix does not.
func TestIsOrphanTmpFile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "env legacy temp", input: "app.env.12345.7" + tmpSuffix, want: true},
		{name: "legacy temp whose pid and counter carry zero digits", input: "app.env.1024.10" + tmpSuffix, want: true},
		{name: "bare dotenv legacy temp", input: ".env.99999.1" + tmpSuffix, want: true},
		{name: "non-env legacy temp", input: "config.yaml.4242.2" + tmpSuffix, want: true},
		{name: "json legacy temp", input: "secrets.json.1.1" + tmpSuffix, want: true},
		{name: "v3 random temp", input: "app.env.0123456789abcdef0123456789abcdef" + tmpSuffix, want: true},
		{name: "marker alone", input: tmpSuffix, want: false},
		{name: "malformed random token", input: "app.env.not-hex" + tmpSuffix, want: false},
		{name: "plain env file", input: "app.env", want: false},
		{name: "ciphertext source", input: "app.env" + encSuffix, want: false},
		{name: "decrypted dotenv", input: ".env", want: false},
		{name: "non env file", input: "config.txt", want: false},
		{name: "legacy bare suffix no longer matched", input: ".env.tmp", want: false},
		{name: "legacy pid-keyed suffix no longer matched", input: "app.env.tmp.12345.7", want: false},
		{name: "marker not at end", input: "note" + tmpSuffix + ".bak", want: false},
		{name: "marker substring missing leading dot", input: "fileage-decrypt-tmp", want: false},
		// outputRelFor refuses a bare ".enc" source, so no pass can generate
		// either of these two empty-output-name shapes.
		{name: "random token with no output name", input: ".0123456789abcdef0123456789abcdef" + tmpSuffix, want: false},
		{name: "legacy pid/counter with no output name", input: ".12345.7" + tmpSuffix, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOrphanTmpFile(tc.input); got != tc.want {
				t.Errorf("isOrphanTmpFile(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
