package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTrackDB(t *testing.T) {
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Could not get working directory: %v", err)
	}
	absolute := filepath.Join(t.TempDir(), "bans.db")

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"default in working directory", "", filepath.Join(workingDir, "fail2ban-dashboard.db")},
		{"relative path", filepath.Join("data", "bans.db"), filepath.Join(workingDir, "data", "bans.db")},
		{"absolute path", absolute, absolute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := ResolveTrackDB(tt.input); result != tt.expected {
				t.Errorf("ResolveTrackDB(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}
