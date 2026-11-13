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
	userOnlyAttrs := []string{
		`unknownAttr eq "test"`,
		`userName sw "val_"`,
		`active eq true`,
		`name.familyName eq "Smith"`,
		`emails.value co "@test.com"`,
		`emails pr`,
		`emails[type eq "work"]`,
		`urn:ietf:params:scim:schemas:core:2.0:User:displayName eq "test"`,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "QA"`,
	}
	for _, f := range userOnlyAttrs {
		_, err := ParseGroupFilter(f, 1)
		if err == nil {
			t.Fatalf("expected error for non-group filter attribute: %s", f)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "unknown attribute") {
			t.Fatalf("expected 'unknown attribute' error for %q, got: %v", f, err)
		}
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
	if ResolveUserSortAttribute("emails") != "emails" {
		t.Fatalf("unexpected user sort for emails")
	}
	if ResolveUserSortAttribute("emails.value") != "emails" {
		t.Fatalf("unexpected user sort for emails.value")
	}
	if ResolveUserSortAttribute("email") != "emails" {
		t.Fatalf("unexpected user sort for email")
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
		{"2024-01-01", false},
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

	// Date-only without time must be rejected per RFC 7643 §2.3.5
	if _, err := ParseUserFilter(`meta.created gt "2024-01-01"`, 1); err == nil {
		t.Fatalf("expected error for date-only on meta.created")
	}

	// Substring operators rejected on dateTime
	invalidOps := []string{"co", "sw", "ew"}
	for _, op := range invalidOps {
		if _, err := ParseUserFilter(`meta.created `+op+` "2024-01-01T00:00:00Z"`, 1); err == nil {
			t.Fatalf("expected error for %s on meta.created", op)
		}
		if _, err := ParseUserFilter(`meta.lastModified `+op+` "2024-01-01T00:00:00Z"`, 1); err == nil {
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

	// Unknown sub-attribute inside value path (isBooleanAttr must not be context-blind)
	if _, err := ParseUserFilter(`emails[active eq true].value eq "x"`, 1); err == nil {
		t.Fatalf("expected error for active in emails value path")
	} else if !strings.Contains(err.Error(), "unknown sub-attribute 'active' for 'emails'") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Valid value path boolean
	if _, err := ParseUserFilter(`emails[primary eq true].value eq "x"`, 1); err != nil {
		t.Fatalf("unexpected error for valid primary eq true in value path: %v", err)
	}

	// Boolean inner pr must not compile to a primaryFlag:false constraint
	resInnerPr, err := ParseUserFilter(`emails[primary pr].value eq "x"`, 1)
	if err != nil {
		t.Fatalf("unexpected error for primary pr in value path: %v", err)
	}
	if !strings.Contains(resInnerPr.SQL, "(elem->>'primaryFlag') IS NOT NULL") {
		t.Fatalf("expected '(elem->>'primaryFlag') IS NOT NULL' in SQL, got %s", resInnerPr.SQL)
	}
	if len(resInnerPr.Args) != 1 || resInnerPr.Args[0] != "x" {
		t.Fatalf("expected single arg 'x' for primary pr, got %v", resInnerPr.Args)
	}

	// Value path boolean ne inside inner filter
	resInnerNe, err := ParseUserFilter(`emails[primary ne true].value eq "x"`, 1)
	if err != nil {
		t.Fatalf("unexpected error for primary ne true in value path: %v", err)
	}
	if !strings.Contains(resInnerNe.SQL, "((elem->>'primaryFlag') != $1 OR (elem->>'primaryFlag') IS NULL)") {
		t.Fatalf("expected negation clause in SQL, got %s", resInnerNe.SQL)
	}
	if len(resInnerNe.Args) != 2 || resInnerNe.Args[0] != "true" || resInnerNe.Args[1] != "x" {
		t.Fatalf("expected args ['true', 'x'], got %v", resInnerNe.Args)
	}

	// Value path boolean as subAttr (eq vs ne)
	resSubEq, err := ParseUserFilter(`emails[type eq "work"].primary eq true`, 1)
	if err != nil {
		t.Fatalf("unexpected error for emails[...].primary eq true: %v", err)
	}
	if !strings.Contains(resSubEq.SQL, "(elem->>'primaryFlag') = $2") {
		t.Fatalf("expected '(elem->>'primaryFlag') = $2' in SQL, got %s", resSubEq.SQL)
	}
	if len(resSubEq.Args) != 2 || resSubEq.Args[0] != "work" || resSubEq.Args[1] != "true" {
		t.Fatalf("expected args ['work', 'true'], got %v", resSubEq.Args)
	}

	resSubNe, err := ParseUserFilter(`emails[type eq "work"].primary ne true`, 1)
	if err != nil {
		t.Fatalf("unexpected error for emails[...].primary ne true: %v", err)
	}
	if !strings.Contains(resSubNe.SQL, "((elem->>'primaryFlag') != $2 OR (elem->>'primaryFlag') IS NULL)") {
		t.Fatalf("expected negation clause in SQL, got %s", resSubNe.SQL)
	}
	if len(resSubNe.Args) != 2 || resSubNe.Args[0] != "work" || resSubNe.Args[1] != "true" {
		t.Fatalf("expected args ['work', 'true'], got %v", resSubNe.Args)
	}

	resSubNeFalse, err := ParseUserFilter(`emails[type eq "work"].primary ne false`, 1)
	if err != nil {
		t.Fatalf("unexpected error for emails[...].primary ne false: %v", err)
	}
	if !strings.Contains(resSubNeFalse.SQL, "((elem->>'primaryFlag') != $2 OR (elem->>'primaryFlag') IS NULL)") {
		t.Fatalf("expected negation clause in SQL, got %s", resSubNeFalse.SQL)
	}
	if len(resSubNeFalse.Args) != 2 || resSubNeFalse.Args[0] != "work" || resSubNeFalse.Args[1] != "false" {
		t.Fatalf("expected args ['work', 'false'], got %v", resSubNeFalse.Args)
	}

	// Invalid operator or value when primary is subAttr
	if _, err := ParseUserFilter(`emails[type eq "work"].primary gt true`, 1); err == nil {
		t.Fatalf("expected error for emails[...].primary gt true")
	}
	if _, err := ParseUserFilter(`emails[type eq "work"].primary eq "yes"`, 1); err == nil {
		t.Fatalf("expected error for emails[...].primary eq 'yes'")
	}

	// Bracket inside quoted string literal must not terminate value path
	resBracketInString, err := ParseUserFilter(`emails[value eq "a]b"].value eq "x"`, 1)
	if err != nil {
		t.Fatalf("unexpected error for bracket in string: %v", err)
	}
	if len(resBracketInString.Args) != 2 || resBracketInString.Args[0] != "a]b" || resBracketInString.Args[1] != "x" {
		t.Fatalf("expected args ['a]b', 'x'], got %v", resBracketInString.Args)
	}

	// Multi-clause inner filters must be rejected
	if _, err := ParseUserFilter(`emails[type eq "work" and primary eq true].value eq "x"`, 1); err == nil {
		t.Fatalf("expected error for multi-clause inner filter with 'and'")
	}
	if _, err := ParseUserFilter(`emails[type eq "work" or primary eq true].value eq "x"`, 1); err == nil {
		t.Fatalf("expected error for multi-clause inner filter with 'or'")
	}

	// Direct JSON attribute boolean checks: ne is not supported on JSON collections
	if _, err := ParseUserFilter(`emails.primary gt true`, 1); err == nil {
		t.Fatalf("expected error for emails.primary gt true")
	}
	if _, err := ParseUserFilter(`emails.primary eq "invalid"`, 1); err == nil {
		t.Fatalf("expected error for emails.primary eq 'invalid'")
	}
	if _, err := ParseUserFilter(`emails.primary eq true`, 1); err != nil {
		t.Fatalf("unexpected error for emails.primary eq true: %v", err)
	}
	if _, err := ParseUserFilter(`emails.primary ne true`, 1); err == nil {
		t.Fatalf("expected error for emails.primary ne true (unsupported operator)")
	}
	if _, err := ParseUserFilter(`emails.value ne "x"`, 1); err == nil {
		t.Fatalf("expected error for emails.value ne 'x' (unsupported operator)")
	}

	// Members value path filter returns clear message
	if _, err := ParseUserFilter(`members[value eq "x"]`, 1); err == nil {
		t.Fatalf("expected error for members value path filter")
	} else if !strings.Contains(err.Error(), "value path filters on 'members' are not supported") {
		t.Fatalf("unexpected error message for members: %v", err)
	}

	// Direct emails.display eq is case-insensitive
	resDisplay, err := ParseUserFilter(`emails.display eq "Work"`, 1)
	if err != nil {
		t.Fatalf("unexpected error for emails.display eq 'Work': %v", err)
	}
	if !strings.Contains(resDisplay.SQL, "LOWER(") {
		t.Fatalf("expected LOWER() in SQL for emails.display, got %s", resDisplay.SQL)
	}

	// Value path gt is lowercased and SQL includes jsonb_typeof check
	resGt, err := ParseUserFilter(`emails[type gt "work"].value eq "x"`, 1)
	if err != nil {
		t.Fatalf("unexpected error for emails[type gt work]: %v", err)
	}
	if !strings.Contains(resGt.SQL, "jsonb_typeof(emails::jsonb) = 'array'") {
		t.Fatalf("expected jsonb_typeof guard in SQL, got %s", resGt.SQL)
	}
	if !strings.Contains(resGt.SQL, "LOWER(elem->>'type') > LOWER($1)") {
		t.Fatalf("expected LOWER(elem->>'type') > LOWER($1) in SQL, got %s", resGt.SQL)
	}
}

func TestParseFilter_MetaResourceType(t *testing.T) {
	resUser, err := ParseUserFilter(`meta.resourceType eq "User"`, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resUser.SQL, "'User'::text") {
		t.Fatalf("expected 'User'::text in SQL, got %s", resUser.SQL)
	}
	if len(resUser.Args) != 1 || resUser.Args[0] != "User" {
		t.Fatalf("expected Arg 'User', got %v", resUser.Args)
	}

	resGroup, err := ParseGroupFilter(`meta.resourceType eq "Group"`, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resGroup.SQL, "'Group'::text") {
		t.Fatalf("expected 'Group'::text in SQL, got %s", resGroup.SQL)
	}
	if len(resGroup.Args) != 1 || resGroup.Args[0] != "Group" {
		t.Fatalf("expected Arg 'Group', got %v", resGroup.Args)
	}

	resCase, err := ParseUserFilter(`meta.resourceType eq "user"`, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resCase.SQL, "LOWER('User'::text) = LOWER($1)") {
		t.Fatalf("expected LOWER expression, got %s", resCase.SQL)
	}
}

func TestParseFilter_UnconsumedTrailingTokens(t *testing.T) {
	testCases := []struct {
		name    string
		filter  string
		isGroup bool
	}{
		{"user unmatched closing paren", `userName eq "alice")`, false},
		{"user extra closing paren", `(userName eq "alice"))`, false},
		{"user trailing identifier", `userName eq "alice" extra`, false},
		{"user consecutive expressions without op", `userName eq "alice" userName eq "bob"`, false},
		{"group unmatched closing paren", `displayName eq "admins")`, true},
		{"group extra closing paren", `(displayName eq "admins"))`, true},
		{"group trailing token", `displayName eq "admins" garbage`, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.isGroup {
				_, err = ParseGroupFilter(tc.filter, 2)
			} else {
				_, err = ParseUserFilter(tc.filter, 2)
			}
			if err == nil {
				t.Fatalf("expected error for filter with trailing tokens: %s", tc.filter)
			}
			scimErr, ok := err.(*ScimError)
			if !ok {
				t.Fatalf("expected *ScimError, got %T: %v", err, err)
			}
			if scimErr.Status != 400 {
				t.Errorf("expected status 400, got %d", scimErr.Status)
			}
			if scimErr.ScimType != "invalidFilter" {
				t.Errorf("expected scimType 'invalidFilter', got %s", scimErr.ScimType)
			}
			if !strings.Contains(scimErr.Detail, "unexpected token") {
				t.Errorf("expected detail to contain 'unexpected token', got %s", scimErr.Detail)
			}
		})
	}
}

func TestParseUserFilter_ExternalId_CaseExact_FLT45(t *testing.T) {
	// FLT_45: externalId has caseExact: true per RFC 7643 §3.1.
	// Filtering on externalId must generate case-sensitive comparison (no LOWER() wrap).
	res, err := ParseUserFilter(`externalId eq "MyExternalId"`, 1)
	if err != nil {
		t.Fatalf("unexpected error parsing externalId filter: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil filter result")
	}
	if strings.Contains(res.SQL, "LOWER") || strings.Contains(res.SQL, "lower") {
		t.Fatalf("expected case-exact comparison without LOWER(), got SQL: %s", res.SQL)
	}
	expectedSQL := "external_id = $1"
	if res.SQL != expectedSQL {
		t.Fatalf("expected SQL %q, got %q", expectedSQL, res.SQL)
	}
	if len(res.Args) != 1 || res.Args[0] != "MyExternalId" {
		t.Fatalf("expected arg 'MyExternalId', got %v", res.Args)
	}

	// Also verify group filter on externalId
	gres, err := ParseGroupFilter(`externalId eq "GroupExtId"`, 1)
	if err != nil {
		t.Fatalf("unexpected error parsing group externalId filter: %v", err)
	}
	if strings.Contains(gres.SQL, "LOWER") || strings.Contains(gres.SQL, "lower") {
		t.Fatalf("expected case-exact group comparison without LOWER(), got SQL: %s", gres.SQL)
	}
	if gres.SQL != expectedSQL {
		t.Fatalf("expected SQL %q, got %q", expectedSQL, gres.SQL)
	}
}

func TestFilter_EmptyBracketAndCrossResourceRootSearch(t *testing.T) {
	if _, err := ParseUserFilter(`emails[]`, 2); err == nil {
		t.Fatal("expected error for empty valuePath bracket emails[]")
	}

	if res, err := ParseUserFilter(`schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`, 2); err != nil || res == nil {
		t.Fatalf("expected schemas eq filter on User to succeed, got err=%v", err)
	}

	if res, err := ParseGroupFilter(`members.value eq "00000000-0000-0000-0000-000000000001"`, 2); err != nil || res == nil {
		t.Fatalf("expected members.value filter on Group to succeed, got err=%v", err)
	}

	// Root cross-resource filter: userName eq "u1" and members pr
	// User parser evaluates `members pr` as FALSE; Group parser evaluates `userName eq "u1"` as FALSE.
	uRes, err := ParseUserFilterForRoot(`userName eq "u1" and members pr`, 2)
	if err != nil {
		t.Fatalf("ParseUserFilterForRoot failed on cross-resource filter: %v", err)
	}
	if !strings.Contains(uRes.SQL, "FALSE") {
		t.Fatalf("expected FALSE term in User SQL for Group-only attribute 'members', got: %s", uRes.SQL)
	}

	gRes, err := ParseGroupFilterForRoot(`userName eq "u1" or displayName eq "g1"`, 2)
	if err != nil {
		t.Fatalf("ParseGroupFilterForRoot failed on cross-resource filter: %v", err)
	}
	if !strings.Contains(gRes.SQL, "FALSE") || !strings.Contains(gRes.SQL, "display_name") {
		t.Fatalf("expected FALSE OR display_name in Group SQL, got: %s", gRes.SQL)
	}

	// Unknown attribute on both User and Group must still fail in root filter mode
	if _, err := ParseUserFilterForRoot(`totallyUnknownAttr eq "x"`, 2); err == nil {
		t.Fatal("expected unknown attribute to fail in ParseUserFilterForRoot")
	}
}

func TestVersionAgnosticRefFilters_RFC7643_2_4(t *testing.T) {
	targetID := "11111111-2222-3333-4444-555555555555"

	refCases := []struct {
		input string
		want  string
	}{
		{"/Users/" + targetID, targetID},
		{"Users/" + targetID, targetID},
		{"https://legacy.idp.example/scim/v1/Users/" + targetID, targetID},
		{"http://127.0.0.1:8080/ws/aaaa/scim/v2/Users/" + strings.ToUpper(targetID) + "/", targetID},
		{"https://example.com/scim/v1/Groups/" + targetID + "?attributes=displayName", targetID},
		{"http://example.com/Users/alice", ""},
		{"https://" + targetID, ""},
		{targetID, ""},
		{"", ""},
	}
	for _, tc := range refCases {
		if got := ExtractUUIDFromRef(tc.input); got != tc.want {
			t.Fatalf("ExtractUUIDFromRef(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	for _, uri := range []string{
		"/Users/" + targetID,
		"https://legacy.idp.example/scim/v1/Users/" + targetID,
		"https://scim.example.com/scim/v2/Users/" + targetID,
	} {
		gEq, err := ParseGroupFilter(`members.$ref eq "`+uri+`"`, 2)
		if err != nil {
			t.Fatalf("ParseGroupFilter members.$ref eq %q failed: %v", uri, err)
		}
		if !strings.Contains(gEq.SQL, "m.member_value::text") || len(gEq.Args) != 1 || gEq.Args[0] != targetID {
			t.Fatalf("members.$ref eq %q -> SQL=%q Args=%v, want m.member_value::text with arg %q", uri, gEq.SQL, gEq.Args, targetID)
		}

		gNe, err := ParseGroupFilter(`members.$ref ne "`+uri+`"`, 2)
		if err != nil {
			t.Fatalf("ParseGroupFilter members.$ref ne %q failed: %v", uri, err)
		}
		if len(gNe.Args) != 1 || gNe.Args[0] != targetID {
			t.Fatalf("members.$ref ne %q -> Args=%v, want [%q]", uri, gNe.Args, targetID)
		}
	}

	for _, uri := range []string{
		"/Groups/" + targetID,
		"https://legacy.idp.example/scim/v1/Groups/" + targetID,
		"https://scim.example.com/scim/v2/Groups/" + targetID,
	} {
		uGrp, err := ParseUserFilter(`groups.$ref eq "`+uri+`"`, 2)
		if err != nil {
			t.Fatalf("ParseUserFilter groups.$ref eq %q failed: %v", uri, err)
		}
		if !strings.Contains(uGrp.SQL, "m.group_id::text") || len(uGrp.Args) != 1 || uGrp.Args[0] != targetID {
			t.Fatalf("groups.$ref eq %q -> SQL=%q Args=%v, want m.group_id::text with arg %q", uri, uGrp.SQL, uGrp.Args, targetID)
		}
	}

	for _, uri := range []string{
		"/Users/" + targetID,
		"https://legacy.idp.example/scim/v1/Users/" + targetID,
		"https://scim.example.com/scim/v2/Users/" + targetID,
	} {
		uMgr, err := ParseUserFilter(`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.$ref eq "`+uri+`"`, 2)
		if err != nil {
			t.Fatalf("ParseUserFilter manager.$ref eq %q failed: %v", uri, err)
		}
		if !strings.Contains(uMgr.SQL, "enterprise_manager_value") || len(uMgr.Args) != 1 || uMgr.Args[0] != targetID {
			t.Fatalf("manager.$ref eq %q -> SQL=%q Args=%v, want enterprise_manager_value with arg %q", uri, uMgr.SQL, uMgr.Args, targetID)
		}
	}

	nonUUIDMgr, err := ParseUserFilter(`manager.$ref eq "http://example.com/Users/alice"`, 2)
	if err != nil {
		t.Fatalf("ParseUserFilter non-UUID manager.$ref failed: %v", err)
	}
	if !strings.Contains(nonUUIDMgr.SQL, "enterprise_manager_ref") {
		t.Fatalf("expected enterprise_manager_ref fallback for non-UUID URI, got %q", nonUUIDMgr.SQL)
	}
}

func TestBuildJSONAttributeFilter_JsonbArrayElementsAndSpecialChars(t *testing.T) {
	// 1. Direct JSON attribute filter with quotes and backslashes uses jsonb_array_elements
	resQuote, err := ParseUserFilter(`emails.value eq "a\"b\\c@example.com"`, 1)
	if err != nil {
		t.Fatalf("ParseUserFilter with quotes/backslashes failed: %v", err)
	}
	if !strings.Contains(resQuote.SQL, "jsonb_array_elements(emails::jsonb) AS elem") {
		t.Fatalf("expected jsonb_array_elements in SQL, got: %s", resQuote.SQL)
	}
	if !strings.Contains(resQuote.SQL, "LOWER(elem->>'value') = LOWER($1)") {
		t.Fatalf("expected LOWER(elem->>'value') = LOWER($1) in SQL, got: %s", resQuote.SQL)
	}
	if len(resQuote.Args) != 1 || resQuote.Args[0] != `a\"b\\c@example.com` {
		t.Fatalf("unexpected Args: %v", resQuote.Args)
	}

	// 2. Presence filter on JSON sub-attribute checks elem->>'type' IS NOT NULL
	resPr, err := ParseUserFilter(`emails.type pr`, 1)
	if err != nil {
		t.Fatalf("ParseUserFilter emails.type pr failed: %v", err)
	}
	if !strings.Contains(resPr.SQL, "jsonb_array_elements(emails::jsonb) AS elem") || !strings.Contains(resPr.SQL, "(elem->>'type') IS NOT NULL") {
		t.Fatalf("expected jsonb_array_elements with elem->>'type' IS NOT NULL, got: %s", resPr.SQL)
	}

	// 3. Control characters (e.g., tab) in LIKE value are preserved by escapeLikeValue
	resCtrl, err := ParseUserFilter("displayName co \"a\tb\"", 1)
	if err != nil {
		t.Fatalf("ParseUserFilter with tab character failed: %v", err)
	}
	if len(resCtrl.Args) != 1 || resCtrl.Args[0] != "%a\tb%" {
		t.Fatalf("expected control char preserved in LIKE arg '%%a\\tb%%', got %q", resCtrl.Args)
	}
}

func TestParseFilter_LengthTokenAndDepthLimits(t *testing.T) {
	t.Run("oversized filter string returns 400 invalidFilter", func(t *testing.T) {
		oversized := `userName eq "` + strings.Repeat("a", MaxFilterLength) + `"`
		for _, fn := range []func(string, int) (*FilterResult, error){ParseUserFilter, ParseGroupFilter} {
			_, err := fn(oversized, 1)
			if err == nil {
				t.Fatal("expected error for filter exceeding MaxFilterLength")
			}
			scimErr, ok := err.(*ScimError)
			if !ok {
				t.Fatalf("expected *ScimError, got %T: %v", err, err)
			}
			if scimErr.Status != 400 || scimErr.ScimType != "invalidFilter" {
				t.Fatalf("expected 400 invalidFilter, got status=%d scimType=%q detail=%q", scimErr.Status, scimErr.ScimType, scimErr.Detail)
			}
		}
	})

	t.Run("excessive token count returns 400 invalidFilter", func(t *testing.T) {
		clauses := make([]string, 70) // 70 * 3 + 69 = 279 tokens > MaxFilterTokens (200)
		for i := range clauses {
			clauses[i] = `userName eq "a"`
		}
		tooManyTokens := strings.Join(clauses, " or ")
		_, err := ParseUserFilter(tooManyTokens, 1)
		if err == nil {
			t.Fatal("expected error for filter exceeding MaxFilterTokens")
		}
		scimErr, ok := err.(*ScimError)
		if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidFilter" {
			t.Fatalf("expected 400 invalidFilter, got %T: %v", err, err)
		}
	})

	t.Run("deeply nested parentheses or NOT expressions return 400 invalidFilter", func(t *testing.T) {
		deepParens := strings.Repeat("(", MaxFilterDepth+2) + `userName eq "alice"` + strings.Repeat(")", MaxFilterDepth+2)
		_, err := ParseUserFilter(deepParens, 1)
		if err == nil {
			t.Fatal("expected error for deeply nested parentheses")
		}
		scimErr, ok := err.(*ScimError)
		if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidFilter" {
			t.Fatalf("expected 400 invalidFilter, got %T: %v", err, err)
		}

		deepNot := strings.Repeat("not (", MaxFilterDepth+1) + `userName eq "alice"` + strings.Repeat(")", MaxFilterDepth+1)
		_, err = ParseUserFilter(deepNot, 1)
		if err == nil {
			t.Fatal("expected error for deeply nested NOT expression")
		}
		scimErr, ok = err.(*ScimError)
		if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidFilter" {
			t.Fatalf("expected 400 invalidFilter, got %T: %v", err, err)
		}

		// Nesting at MaxFilterDepth is still accepted
		okParens := strings.Repeat("(", MaxFilterDepth) + `userName eq "alice"` + strings.Repeat(")", MaxFilterDepth)
		if _, err := ParseUserFilter(okParens, 1); err != nil {
			t.Fatalf("expected nesting at MaxFilterDepth (%d) to succeed, got: %v", MaxFilterDepth, err)
		}
	})
}


