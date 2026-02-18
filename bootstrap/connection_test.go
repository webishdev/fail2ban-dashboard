package bootstrap

import "testing"

func TestSupportedVersions(t *testing.T) {
	if len(supportedVersions) == 0 {
		t.Error("No supported versions defined")
	}

	// Test that supported versions contains expected version
	found := false
	for _, version := range supportedVersions {
		if version == "1.1.0" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected version 1.1.0 not found in supported versions")
	}
}
