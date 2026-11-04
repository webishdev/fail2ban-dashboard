package bootstrap

import "testing"

func TestValidateRefreshSeconds(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		// Valid inputs
		{"valid minimum", 10, 10},
		{"valid maximum", 600, 600},
		{"valid middle", 30, 30},
		{"valid arbitrary", 120, 120},

		// Invalid inputs - below minimum
		{"below minimum by 1", 9, 30},
		{"zero", 0, 30},
		{"negative", -5, 30},

		// Invalid inputs - above maximum
		{"above maximum by 1", 601, 30},
		{"far above maximum", 1000, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRefreshSeconds(tt.input)
			if result != tt.expected {
				t.Errorf("ValidateRefreshSeconds(%d) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}
