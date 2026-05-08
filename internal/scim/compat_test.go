package scim

import "testing"

func TestParseCompatMode(t *testing.T) {
	tests := []struct {
		input    string
		expected CompatMode
	}{
		{"ms", CompatMS},
		{"MS", CompatMS},
		{"mS", CompatMS},
		{"Ms", CompatMS},
		{"", CompatNone},
		{"none", CompatNone},
		{"something", CompatNone},
		{"MS ", CompatNone}, // should not trim space
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseCompatMode(tt.input); got != tt.expected {
				t.Errorf("ParseCompatMode(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
