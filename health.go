package main

// File-based healthcheck for distroless containers, delegating to
// github.com/cplieger/health.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cplieger/health"
)

// healthMarkerPath is the default marker location.
const healthMarkerPath = health.DefaultPath

// healthMarker wraps *health.Marker to preserve the internal API used
// by main.go and tests.
type healthMarker struct {
	*health.Marker
	degraded bool
}

// newHealthMarker constructs a marker and detects degraded mode.
func newHealthMarker(path string) *healthMarker {
	m := health.NewMarker(path)
	degraded := probeHealthDir(path) != nil
	return &healthMarker{Marker: m, degraded: degraded}
}

// runProbe delegates to health.RunProbe (calls os.Exit).
func runProbe(path string) {
	health.RunProbe(path)
}

// probeCheck delegates to health.ProbeCheck (testable, no os.Exit).
func probeCheck(path string) int {
	return health.ProbeCheck(path)
}

// probeHealthDir verifies the marker's parent directory is writable by
// creating and deleting a temp file.
func probeHealthDir(path string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".health-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close probe: %w", closeErr)
	}
	if rmErr := os.Remove(name); rmErr != nil {
		return fmt.Errorf("remove probe: %w", rmErr)
	}
	return nil
}
