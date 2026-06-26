package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// BenchmarkDecryptFile measures decryptFile performance with a small representative
// armored-encrypted input to catch performance regressions.
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
	envPath := filepath.Join(tmpDir, "bench.env")

	rootDir, err := os.OpenRoot(tmpDir)
	if err != nil {
		b.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = rootDir.Close() }()

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		// Re-write the encrypted file each iteration since decryptFile overwrites it.
		if err := os.WriteFile(envPath, encrypted, 0o644); err != nil {
			b.Fatalf("write: %v", err)
		}
		status := decryptFile(context.Background(), rootDir, "bench.env", []age.Identity{id})
		if status != fileDecrypted {
			b.Fatalf("decryptFile = %d, want %d (fileDecrypted)", status, fileDecrypted)
		}
	}
}
