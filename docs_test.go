package main

import (
	"os"
	"strings"
	"testing"
)

// TestDocs_name_the_health_file_the_waiting_process_writes pins the health
// file the docs name to the one the waiting process writes and the health
// subcommand reads, and keeps the old /tmp location, which a read-only root no
// longer needs, out of every page.
func TestDocs_name_the_health_file_the_waiting_process_writes(t *testing.T) {
	raw, err := os.ReadFile("docs/monitoring.md")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	_, section, found := strings.Cut(string(raw), "\n## Knowing the app is alive\n")
	if !found {
		t.Fatal("docs/monitoring.md has no Knowing the app is alive section")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	if !strings.Contains(section, "`"+markerPath+"`") {
		t.Errorf("docs/monitoring.md Knowing the app is alive does not name the health file %s", markerPath)
	}
	for _, path := range []string{"README.md", "docs/configuration.md", "docs/hardening.md", "docs/how-it-works.md", "docs/monitoring.md", "compose.yaml"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("Setup: %v", err)
		}
		if strings.Contains(string(raw), "/tmp") {
			t.Errorf("%s names /tmp, want no health file or tmpfs there", path)
		}
	}
}
