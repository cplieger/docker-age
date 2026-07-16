package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// BenchmarkDecryptFile measures decryptFile performance with a small representative
// armored-encrypted input to catch performance regressions. Under the v3
// sibling-output model the source survives every pass, so the fixture is
// written once and each iteration re-decrypts it (overwriting the sibling).
func BenchmarkDecryptFile(b *testing.B) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatalf("generate identity: %v", err)
	}

	original := []byte("BENCH_KEY=benchmark_value_12345\n")
	encrypted, err := encryptArmored(original, id.Recipient())
	if err != nil {
		b.Fatalf("encrypt: %v", err)
	}

	tmpDir := b.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "bench.env"+encSuffix), encrypted, 0o644); err != nil {
		b.Fatalf("write: %v", err)
	}

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		b.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		status := decryptFile(context.Background(), rootDir, "bench.env"+encSuffix, []age.Identity{id})
		if status != fileDecrypted {
			b.Fatalf("decryptFile = %d, want %d (fileDecrypted)", status, fileDecrypted)
		}
	}
}
