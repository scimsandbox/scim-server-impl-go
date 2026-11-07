package handler

import (
	"testing"
)

func TestCheckETagMatch(t *testing.T) {
	tests := []struct {
		name     string
		ifMatch  string
		version  int64
		expected bool
	}{
		{
			name:     "empty header matches any version",
			ifMatch:  "",
			version:  1,
			expected: true,
		},
		{
			name:     "wildcard * matches existing resource version",
			ifMatch:  "*",
			version:  1,
			expected: true,
		},
		{
			name:     "wildcard * with leading and trailing whitespace matches",
			ifMatch:  "  *  ",
			version:  42,
			expected: true,
		},
		{
			name:     "matching weak ETag succeeds",
			ifMatch:  `W/"1"`,
			version:  1,
			expected: true,
		},
		{
			name:     "matching weak ETag with whitespace succeeds",
			ifMatch:  `  W/"5"  `,
			version:  5,
			expected: true,
		},
		{
			name:     "mismatched weak ETag fails",
			ifMatch:  `W/"999999"`,
			version:  1,
			expected: false,
		},
		{
			name:     "synthetic stale ETag fails",
			ifMatch:  `W/"synthetic-stale-etag-99999"`,
			version:  1,
			expected: false,
		},
		{
			name:     "strong ETag does not match weak ETag format",
			ifMatch:  `"1"`,
			version:  1,
			expected: false,
		},
		{
			name:     "comma-separated list containing matching weak ETag succeeds",
			ifMatch:  `W/"1", W/"2", W/"3"`,
			version:  2,
			expected: true,
		},
		{
			name:     "comma-separated list containing wildcard * succeeds",
			ifMatch:  `W/"99", *`,
			version:  1,
			expected: true,
		},
		{
			name:     "comma-separated list with no matching ETag fails",
			ifMatch:  `W/"10", W/"20"`,
			version:  1,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkETagMatch(tc.ifMatch, tc.version)
			if got != tc.expected {
				t.Errorf("checkETagMatch(%q, %d) = %v; want %v", tc.ifMatch, tc.version, got, tc.expected)
			}
		})
	}
}
