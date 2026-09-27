package handler

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

func TestNormalizeBulkPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "canonical users path",
			input:    "/Users",
			expected: "/Users",
		},
		{
			name:     "double leading slash users path (production issue)",
			input:    "//Users",
			expected: "/Users",
		},
		{
			name:     "triple leading slash users path",
			input:    "///Users",
			expected: "/Users",
		},
		{
			name:     "relative users path without leading slash",
			input:    "Users",
			expected: "/Users",
		},
		{
			name:     "users path with trailing slash",
			input:    "/Users/",
			expected: "/Users",
		},
		{
			name:     "double slash with trailing slash",
			input:    "//Users/",
			expected: "/Users",
		},
		{
			name:     "canonical groups path",
			input:    "/Groups",
			expected: "/Groups",
		},
		{
			name:     "double leading slash groups path",
			input:    "//Groups",
			expected: "/Groups",
		},
		{
			name:     "canonical resource item path",
			input:    "/Users/123e4567-e89b-12d3-a456-426614174000",
			expected: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:     "double leading slash resource item path",
			input:    "//Users/123e4567-e89b-12d3-a456-426614174000",
			expected: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:     "redundant internal slashes in resource item path",
			input:    "//Users//123e4567-e89b-12d3-a456-426614174000",
			expected: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace string",
			input:    "   ",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeBulkPath(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeBulkPath(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseBulkPath(t *testing.T) {
	validUUID := uuid.New()
	validUUIDStr := validUUID.String()

	tests := []struct {
		name         string
		path         string
		wantType     string
		wantID       uuid.UUID
		wantErr      bool
		wantScimType string
		wantStatus   int
	}{
		{
			name:       "valid Users path canonical",
			path:       "/Users/" + validUUIDStr,
			wantType:   "Users",
			wantID:     validUUID,
			wantErr:    false,
		},
		{
			name:       "valid Users path double slash",
			path:       "//Users/" + validUUIDStr,
			wantType:   "Users",
			wantID:     validUUID,
			wantErr:    false,
		},
		{
			name:       "valid Users path no leading slash",
			path:       "Users/" + validUUIDStr,
			wantType:   "Users",
			wantID:     validUUID,
			wantErr:    false,
		},
		{
			name:       "valid Users path lowercase",
			path:       "/users/" + validUUIDStr,
			wantType:   "Users",
			wantID:     validUUID,
			wantErr:    false,
		},
		{
			name:       "valid Groups path canonical",
			path:       "/Groups/" + validUUIDStr,
			wantType:   "Groups",
			wantID:     validUUID,
			wantErr:    false,
		},
		{
			name:       "valid Groups path double slash",
			path:       "//Groups/" + validUUIDStr,
			wantType:   "Groups",
			wantID:     validUUID,
			wantErr:    false,
		},
		{
			name:       "valid Groups path lowercase",
			path:       "/groups/" + validUUIDStr,
			wantType:   "Groups",
			wantID:     validUUID,
			wantErr:    false,
		},
		{
			name:         "missing ID in Users path",
			path:         "/Users",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "missing ID in double slash Users path",
			path:         "//Users",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "trailing slash only no ID",
			path:         "/Users/",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "unknown resource type",
			path:         "/UnknownEndpoint/" + validUUIDStr,
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "unknown resource type double slash",
			path:         "//UnknownEndpoint/" + validUUIDStr,
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "invalid UUID format",
			path:         "/Users/not-a-uuid",
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resType, id, err := parseBulkPath(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseBulkPath(%q) expected error, got nil", tc.path)
				}
				var scimErr *scim.ScimError
				if errors.As(err, &scimErr) {
					if scimErr.Status != tc.wantStatus {
						t.Errorf("parseBulkPath(%q) status = %d; want %d", tc.path, scimErr.Status, tc.wantStatus)
					}
					if scimErr.ScimType != tc.wantScimType {
						t.Errorf("parseBulkPath(%q) scimType = %q; want %q", tc.path, scimErr.ScimType, tc.wantScimType)
					}
				} else {
					t.Errorf("parseBulkPath(%q) error is not a ScimError: %v", tc.path, err)
				}
			} else {
				if err != nil {
					t.Fatalf("parseBulkPath(%q) unexpected error: %v", tc.path, err)
				}
				if resType != tc.wantType {
					t.Errorf("parseBulkPath(%q) resourceType = %q; want %q", tc.path, resType, tc.wantType)
				}
				if id != tc.wantID {
					t.Errorf("parseBulkPath(%q) id = %v; want %v", tc.path, id, tc.wantID)
				}
			}
		})
	}
}
