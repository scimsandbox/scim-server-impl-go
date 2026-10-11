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
    if _, err := ParseUserFilter(`meta.lastModified gt "not-an-iso-8601-date"`, 1); err == nil {
        t.Fatalf("expected error for malformed dateTime in filter")
    }
    if _, err := ParseUserFilter(`active gt true`, 1); err == nil {
        t.Fatalf("expected error for gt on boolean attribute")
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

func TestIsValidDateTime_TableDriven(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"2024-01-01T00:00:00Z", true},
		{"2024-01-01T15:04:05+02:00", true},
		{"2024-01-01T15:04:05-07:00", true},
		{"2024-01-01T15:04:05.123456Z", true},
		{"2024-01-01T15:04:05.123456+02:00", true},
		{"2024-01-01T15:04:05", true},
		{"2024-01-01T15:04:05.999999999", true},
		{"2024-01-01 15:04:05", true},
		{"2024-01-01 15:04:05.123456", true},
		{"2024-01-01", true},
		{"not-an-iso-8601-date", false},
		{"2024-02-30T00:00:00Z", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isValidDateTime(tt.input)
		if got != tt.valid {
			t.Errorf("isValidDateTime(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

func TestParseUserFilter_DateTimeNormalizationAndOperators(t *testing.T) {
	// Offset should be normalized to UTC in Args
	res, err := ParseUserFilter(`meta.created gt "2024-01-01T15:00:00+02:00"`, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(res.Args))
	}
	argStr, ok := res.Args[0].(string)
	if !ok {
		t.Fatalf("expected string arg, got %T", res.Args[0])
	}
	if !strings.HasPrefix(argStr, "2024-01-01T13:00:00") || !strings.HasSuffix(argStr, "Z") {
		t.Fatalf("expected normalized UTC dateTime (13:00:00Z), got %s", argStr)
	}

	// Substring operators rejected on dateTime
	invalidOps := []string{"co", "sw", "ew"}
	for _, op := range invalidOps {
		if _, err := ParseUserFilter(`meta.created `+op+` "2024-01-01"`, 1); err == nil {
			t.Fatalf("expected error for %s on meta.created", op)
		}
		if _, err := ParseUserFilter(`meta.lastModified `+op+` "2024-01-01"`, 1); err == nil {
			t.Fatalf("expected error for %s on meta.lastModified", op)
		}
	}
}

func TestParseUserFilter_ActiveBooleanConsistency(t *testing.T) {
	// active eq true -> bool argument true
	resEqTrue, err := ParseUserFilter("active eq true", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resEqTrue.SQL != "active = $1" {
		t.Fatalf("expected SQL 'active = $1', got %s", resEqTrue.SQL)
	}
	if resEqTrue.Args[0] != true {
		t.Fatalf("expected bool arg true, got %v (%T)", resEqTrue.Args[0], resEqTrue.Args[0])
	}

	// active eq false -> bool argument false
	resEqFalse, err := ParseUserFilter("active eq false", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resEqFalse.Args[0] != false {
		t.Fatalf("expected bool arg false, got %v (%T)", resEqFalse.Args[0], resEqFalse.Args[0])
	}

	// active ne true -> bool argument true
	resNeTrue, err := ParseUserFilter("active ne true", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resNeTrue.SQL != "(active != $1 OR active IS NULL)" {
		t.Fatalf("expected SQL '(active != $1 OR active IS NULL)', got %s", resNeTrue.SQL)
	}
	if resNeTrue.Args[0] != true {
		t.Fatalf("expected bool arg true, got %v (%T)", resNeTrue.Args[0], resNeTrue.Args[0])
	}

	// active ne false -> bool argument false
	resNeFalse, err := ParseUserFilter("active ne false", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resNeFalse.Args[0] != false {
		t.Fatalf("expected bool arg false, got %v (%T)", resNeFalse.Args[0], resNeFalse.Args[0])
	}

	// Invalid boolean values
	if _, err := ParseUserFilter(`active eq "yes"`, 1); err == nil {
		t.Fatalf("expected error for active eq 'yes'")
	}
	if _, err := ParseUserFilter(`active ne "no"`, 1); err == nil {
		t.Fatalf("expected error for active ne 'no'")
	}

	// Non-boolean attribute with value "true" must NOT be converted to bool
	resUserTrue, err := ParseUserFilter(`userName eq "true"`, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resUserTrue.Args[0] != "true" {
		t.Fatalf("expected string 'true', got %v (%T)", resUserTrue.Args[0], resUserTrue.Args[0])
	}
}

func TestParseUserFilter_ValuePathBooleans(t *testing.T) {
	// Invalid operator on primary inside value path filter
	if _, err := ParseUserFilter(`emails[primary gt true].value eq "x"`, 1); err == nil {
		t.Fatalf("expected error for gt on primary in value path")
	}
	if _, err := ParseUserFilter(`emails[primary co true].value eq "x"`, 1); err == nil {
		t.Fatalf("expected error for co on primary in value path")
	}
	if _, err := ParseUserFilter(`emails[primary eq "foo"].value eq "x"`, 1); err == nil {
		t.Fatalf("expected error for invalid boolean value foo in value path")
	}

	// Valid value path boolean
	if _, err := ParseUserFilter(`emails[primary eq true].value eq "x"`, 1); err != nil {
		t.Fatalf("unexpected error for valid primary eq true in value path: %v", err)
	}

	// Invalid operator when primary is subAttr
	if _, err := ParseUserFilter(`emails[type eq "work"].primary gt true`, 1); err == nil {
		t.Fatalf("expected error for emails[...].primary gt true")
	}

	// Direct JSON attribute boolean checks
	if _, err := ParseUserFilter(`emails.primary gt true`, 1); err == nil {
		t.Fatalf("expected error for emails.primary gt true")
	}
	if _, err := ParseUserFilter(`emails.primary eq "invalid"`, 1); err == nil {
		t.Fatalf("expected error for emails.primary eq 'invalid'")
	}
	if _, err := ParseUserFilter(`emails.primary eq true`, 1); err != nil {
		t.Fatalf("unexpected error for emails.primary eq true: %v", err)
	}
}
