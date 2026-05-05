package scim

import (
    "testing"
)

func TestBuildErrorBody_WithScimType(t *testing.T) {
    err := NewScimError(400, "invalidValue", "some detail")
    if err.Status != 400 {
        t.Fatalf("Status = %d, want 400", err.Status)
    }
    if err.ScimType != "invalidValue" {
        t.Fatalf("ScimType = %q, want invalidValue", err.ScimType)
    }
    if err.Detail != "some detail" {
        t.Fatalf("Detail = %q, want some detail", err.Detail)
    }
}

func TestBuildErrorBody_WithoutScimType(t *testing.T) {
    err := NewScimError(500, "", "internal error")
    if err.Status != 500 {
        t.Fatalf("Status = %d, want 500", err.Status)
    }
    if err.ScimType != "" {
        t.Fatalf("ScimType = %q, want empty", err.ScimType)
    }
    if err.Detail != "internal error" {
        t.Fatalf("Detail = %q, want internal error", err.Detail)
    }
    if err.Error() != "SCIM error 500: internal error" {
        t.Fatalf("Error() = %q", err.Error())
    }
}
