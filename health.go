package main

// File-based healthcheck for distroless containers, delegating to
// github.com/cplieger/health. The library handles degraded mode (a
// read-only marker dir) internally, so this app keeps only thin wrappers.

import "github.com/cplieger/health"

// healthMarkerPath is the marker location, sourced from the library.
const healthMarkerPath = health.DefaultPath

// healthMarker aliases *health.Marker to preserve the internal API used
// by main.go and tests.
type healthMarker = health.Marker

// newHealthMarker constructs a marker for path.
func newHealthMarker(path string) *healthMarker {
	return health.NewMarker(path)
}

// runProbe delegates to health.RunProbe (calls os.Exit).
func runProbe(path string) {
	health.RunProbe(path)
}

// probeCheck delegates to health.ProbeCheck (testable, no os.Exit).
func probeCheck(path string) int {
	return health.ProbeCheck(path)
}
