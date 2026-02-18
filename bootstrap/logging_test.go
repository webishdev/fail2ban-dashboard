package bootstrap

import "testing"

func TestConfigureLogging_ValidLevels(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{"trace level", "trace"},
		{"debug level", "debug"},
		{"info level", "info"},
		{"warn level", "warn"},
		{"error level", "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ConfigureLogging panicked with valid level %s: %v", tt.logLevel, r)
				}
			}()
			ConfigureLogging(tt.logLevel)
		})
	}
}

func TestConfigureLogging_InvalidLevel(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ConfigureLogging panicked with invalid level: %v", r)
		}
	}()
	ConfigureLogging("invalid")
}

func TestConfigureLogging_EmptyString(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ConfigureLogging panicked with empty string: %v", r)
		}
	}()
	ConfigureLogging("")
}

func TestConfigureLogging_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{"uppercase INFO", "INFO"},
		{"mixed case Debug", "Debug"},
		{"uppercase ERROR", "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ConfigureLogging panicked with %s: %v", tt.logLevel, r)
				}
			}()
			ConfigureLogging(tt.logLevel)
		})
	}
}
