package handler

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

func TestNormalizeBulkPath(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedPath string
		wantErr      bool
		wantScimType string
	}{
		{
			name:         "canonical users path",
			input:        "/Users",
			expectedPath: "/Users",
		},
		{
			name:         "double leading slash users path (production issue)",
			input:        "//Users",
			expectedPath: "/Users",
		},
		{
			name:         "triple leading slash users path",
			input:        "///Users",
			expectedPath: "/Users",
		},
		{
			name:         "relative users path without leading slash",
			input:        "Users",
			expectedPath: "/Users",
		},
		{
			name:         "users path with trailing slash",
			input:        "/Users/",
			expectedPath: "/Users",
		},
		{
			name:         "double slash with trailing slash",
			input:        "//Users/",
			expectedPath: "/Users",
		},
		{
			name:         "canonical groups path",
			input:        "/Groups",
			expectedPath: "/Groups",
		},
		{
			name:         "double leading slash groups path",
			input:        "//Groups",
			expectedPath: "/Groups",
		},
		{
			name:         "canonical resource item path",
			input:        "/Users/123e4567-e89b-12d3-a456-426614174000",
			expectedPath: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:         "double leading slash resource item path",
			input:        "//Users/123e4567-e89b-12d3-a456-426614174000",
			expectedPath: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:         "redundant internal slashes in resource item path",
			input:        "//Users//123e4567-e89b-12d3-a456-426614174000",
			expectedPath: "/Users/123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:         "empty string",
			input:        "",
			expectedPath: "",
		},
		{
			name:         "whitespace string",
			input:        "   ",
			expectedPath: "",
		},
		{
			name:         "dot path traversal rejected",
			input:        "/Users/./123",
			wantErr:      true,
			wantScimType: "invalidPath",
		},
		{
			name:         "dot-dot path traversal rejected",
			input:        "/Users/../Groups/123",
			wantErr:      true,
			wantScimType: "invalidPath",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, _, err := normalizeBulkPath(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeBulkPath(%q) expected error, got nil", tc.input)
				}
				var scimErr *scim.ScimError
				if errors.As(err, &scimErr) {
					if scimErr.ScimType != tc.wantScimType {
						t.Errorf("normalizeBulkPath(%q) scimType = %q; want %q", tc.input, scimErr.ScimType, tc.wantScimType)
					}
				} else {
					t.Errorf("normalizeBulkPath(%q) error is not a ScimError: %v", tc.input, err)
				}
			} else {
				if err != nil {
					t.Fatalf("normalizeBulkPath(%q) unexpected error: %v", tc.input, err)
				}
				if path != tc.expectedPath {
					t.Errorf("normalizeBulkPath(%q) = %q; want %q", tc.input, path, tc.expectedPath)
				}
			}
		})
	}
}

func TestParseBulkTarget_Post(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantType     bulkResourceType
		wantErr      bool
		wantScimType string
		wantStatus   int
	}{
		{
			name:     "valid Users endpoint canonical",
			path:     "/Users",
			wantType: bulkResourceUsers,
		},
		{
			name:     "valid Users endpoint double slash",
			path:     "//Users",
			wantType: bulkResourceUsers,
		},
		{
			name:     "valid Users endpoint lowercase",
			path:     "/users",
			wantType: bulkResourceUsers,
		},
		{
			name:     "valid Groups endpoint canonical",
			path:     "/Groups",
			wantType: bulkResourceGroups,
		},
		{
			name:     "valid Groups endpoint lowercase",
			path:     "/groups",
			wantType: bulkResourceGroups,
		},
		{
			name:         "POST to item path rejected",
			path:         "/Users/123e4567-e89b-12d3-a456-426614174000",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "POST to double slash item path rejected",
			path:         "//Users//123e4567-e89b-12d3-a456-426614174000",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "POST to unknown endpoint rejected",
			path:         "/UnknownEndpoint",
			wantErr:      true,
			wantScimType: "invalidValue",
			wantStatus:   400,
		},
		{
			name:         "POST to traversal path rejected",
			path:         "/Users/../Groups",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
		{
			name:         "POST to empty path rejected",
			path:         "",
			wantErr:      true,
			wantScimType: "invalidPath",
			wantStatus:   400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := parseBulkTarget(tc.path, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseBulkTarget(%q, false) expected error, got nil", tc.path)
				}
				var scimErr *scim.ScimError
				if errors.As(err, &scimErr) {
					if scimErr.Status != tc.wantStatus {
						t.Errorf("parseBulkTarget(%q) status = %d; want %d", tc.path, scimErr.Status, tc.wantStatus)
					}
					if scimErr.ScimType != tc.wantScimType {
						t.Errorf("parseBulkTarget(%q) scimType = %q; want %q", tc.path, scimErr.ScimType, tc.wantScimType)
					}
				} else {
					t.Errorf("parseBulkTarget(%q) error is not a ScimError: %v", tc.path, err)
				}
			} else {
				if err != nil {
					t.Fatalf("parseBulkTarget(%q, false) unexpected error: %v", tc.path, err)
				}
				if target.resourceType != tc.wantType {
					t.Errorf("parseBulkTarget(%q) resourceType = %v; want %v", tc.path, target.resourceType, tc.wantType)
				}
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
		{
			name:         "traversal path rejected",
			path:         "/Users/../Groups/" + validUUIDStr,
			wantErr:      true,
			wantScimType: "invalidPath",
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
