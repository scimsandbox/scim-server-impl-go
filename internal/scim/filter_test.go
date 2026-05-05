package scim

import (
    "strings"
    "testing"
)

func TestParseUserFilter_Empty(t *testing.T) {
    res, err := ParseUserFilter("", 1)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if res != nil {
        t.Fatalf("expected nil result for empty filter, got: %v", res)
    }
}

func TestParseUserFilter_Equals(t *testing.T) {
    res, err := ParseUserFilter(`userName eq "test"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
    if !strings.Contains(res.SQL, "user_name") {
        t.Fatalf("SQL should reference user_name column, got: %s", res.SQL)
    }
}

func TestParseUserFilter_NotEqual(t *testing.T) {
    res, err := ParseUserFilter(`userName ne "test"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
}

func TestParseUserFilter_Contains(t *testing.T) {
    res, err := ParseUserFilter(`userName co "test"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
}

func TestParseUserFilter_StartsWith(t *testing.T) {
    res, err := ParseUserFilter(`userName sw "test"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
}

func TestParseUserFilter_EndsWith(t *testing.T) {
    res, err := ParseUserFilter(`userName ew "test"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
}

func TestParseUserFilter_GreaterThanOnMetaCreated(t *testing.T) {
    res, err := ParseUserFilter(`meta.created gt "2023-01-01T00:00:00Z"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil {
        t.Fatalf("expected non-nil result")
    }
    if !strings.Contains(res.SQL, "created_at") {
        t.Fatalf("meta.created should map to created_at, got: %s", res.SQL)
    }
}

func TestParseUserFilter_PresentOnJsonSubAttribute(t *testing.T) {
    res, err := ParseUserFilter(`name.familyName pr`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
}

func TestParseUserFilter_AndOperator(t *testing.T) {
    res, err := ParseUserFilter(`userName eq "test" and active eq "true"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
    if !strings.Contains(strings.ToUpper(res.SQL), "AND") {
        t.Fatalf("expected AND in SQL, got: %s", res.SQL)
    }
}

func TestParseUserFilter_OrOperator(t *testing.T) {
    res, err := ParseUserFilter(`userName eq "test" or displayName eq "test"`, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
    if !strings.Contains(strings.ToUpper(res.SQL), "OR") {
        t.Fatalf("expected OR in SQL, got: %s", res.SQL)
    }
}

func TestParseUserFilter_ComplexAndOperators(t *testing.T) {
    filter := `(userName eq "test" or name.familyName sw "Smith") and (meta.created gt "2023-01-01T00:00:00Z")`
    res, err := ParseUserFilter(filter, 2)
    if err != nil {
        t.Fatalf("parse failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }

    ops := []string{"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}
    for _, op := range ops {
        if _, err := ParseUserFilter("userName "+op+" \"test\"", 1); err != nil {
            t.Fatalf("operator %s failed: %v", op, err)
        }
    }
}

func TestParseUserFilter_SupportedAttributes(t *testing.T) {
    attrs := []string{"meta.created", "meta.lastModified", "name.familyName", "name.givenName", "displayName", "userName", "externalId", "active"}
    for _, a := range attrs {
        if _, err := ParseUserFilter(a+" pr", 1); err != nil {
            t.Fatalf("attribute %s parse failed: %v", a, err)
        }
    }
}

func TestParseGroupFilter_StartsWith(t *testing.T) {
    res, err := ParseGroupFilter(`displayName sw "test"`, 2)
    if err != nil {
        t.Fatalf("group filter failed: %v", err)
    }
    if res == nil || res.SQL == "" {
        t.Fatalf("expected non-empty result SQL")
    }
}

func TestParseGroupFilter_Basic(t *testing.T) {
    if _, err := ParseGroupFilter("displayName eq \"test\"", 1); err != nil {
        t.Fatalf("group filter failed: %v", err)
    }
}

func TestParseGroupFilter_UnknownAttribute(t *testing.T) {
    _, err := ParseGroupFilter(`unknownAttr eq "test"`, 1)
    if err == nil {
        t.Fatalf("expected error for unknown group filter attribute")
    }
}

func TestParseFilter_Invalid(t *testing.T) {
    if _, err := ParseUserFilter("userName unknownOp \"test\"", 1); err == nil {
        t.Fatalf("expected error for unknown operator")
    }
    if _, err := ParseUserFilter("(userName eq \"test\"", 1); err == nil {
        t.Fatalf("expected error for unmatched paren")
    }
}

func TestParseUserFilter_UnknownAttribute(t *testing.T) {
    _, err := ParseUserFilter(`unknownAttr eq "test"`, 1)
    if err == nil {
        t.Fatalf("expected error for unknown user filter attribute")
    }
}

func TestResolveSortAttributes(t *testing.T) {
    if ResolveUserSortAttribute("") != "user_name" {
        t.Fatalf("unexpected user sort default")
    }
    if ResolveGroupSortAttribute("") != "display_name" {
        t.Fatalf("unexpected group sort default")
    }
    if ResolveUserSortAttribute("userName") != "user_name" {
        t.Fatalf("unexpected user sort for userName")
    }
    if ResolveUserSortAttribute("displayName") != "display_name" {
        t.Fatalf("unexpected user sort for displayName")
    }
    if ResolveUserSortAttribute("meta.created") != "created_at" {
        t.Fatalf("unexpected user sort for meta.created")
    }
    if ResolveGroupSortAttribute("displayName") != "display_name" {
        t.Fatalf("unexpected group sort for displayName")
    }
}
