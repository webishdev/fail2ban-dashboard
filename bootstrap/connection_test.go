package bootstrap

import "slices"

import "testing"

func TestSupportedVersions(t *testing.T) {
	if len(supportedVersions) == 0 {
		t.Error("No supported versions defined")
	}

	// Test that supported versions contains expected version
	found := slices.Contains(supportedVersions, "1.1.1")
	if !found {
		t.Error("Expected version 1.1.1 not found in supported versions")
	}
}
