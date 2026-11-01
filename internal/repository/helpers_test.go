package repository

import (
	"testing"

	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

// --- resolveUserSortColumn ---

func TestResolveUserSortColumn(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{"username", "user_name"},
		{"user_name", "user_name"},
		{"USERNAME", "user_name"},
		{"name.familyname", "name_family_name"},
		{"name_family_name", "name_family_name"},
		{"NAME_FAMILY_NAME", "name_family_name"},
		{"name.givenname", "name_given_name"},
		{"name_given_name", "name_given_name"},
		{"displayname", "display_name"},
		{"display_name", "display_name"},
		{"title", "title"},
		{"emails", userSortEmailsExpression},
		{"emails.value", userSortEmailsExpression},
		{"email", userSortEmailsExpression},
		{"meta.created", "created_at"},
		{"created_at", "created_at"},
		{"meta.lastmodified", "last_modified"},
		{"last_modified", "last_modified"},
		{"externalid", "external_id"},
		{"external_id", "external_id"},
		{"active", "active"},
		{"", "user_name"},
		{"unknown_attr", "user_name"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := resolveUserSortColumn(tc.input)
			if got != tc.want {
				t.Fatalf("resolveUserSortColumn(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestUserSortEmailsExpressionConstant(t *testing.T) {
	t.Parallel()

	const expected = `COALESCE((SELECT elem->>'value' FROM jsonb_array_elements(emails::jsonb) elem WHERE (COALESCE(elem->>'primaryFlag', elem->>'primary'))::boolean IS TRUE LIMIT 1), emails::jsonb->0->>'value')`
	if userSortEmailsExpression != expected {
		t.Fatalf("userSortEmailsExpression = %q, want %q", userSortEmailsExpression, expected)
	}
}

// --- buildOrderClause ---

func TestBuildOrderClause(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		col  string
		dir  string
		want string
	}{
		{"default_ascending", "user_name", "", "ORDER BY user_name ASC NULLS LAST"},
		{"explicit_asc", "user_name", "ASC", "ORDER BY user_name ASC NULLS LAST"},
		{"lowercase_asc", "user_name", "asc", "ORDER BY user_name ASC NULLS LAST"},
		{"full_ascending", "user_name", "ascending", "ORDER BY user_name ASC NULLS LAST"},
		{"explicit_desc", "user_name", "DESC", "ORDER BY user_name DESC NULLS FIRST"},
		{"lowercase_desc", "user_name", "desc", "ORDER BY user_name DESC NULLS FIRST"},
		{"full_descending", "user_name", "descending", "ORDER BY user_name DESC NULLS FIRST"},
		{"mixed_case_descending", "user_name", "Descending", "ORDER BY user_name DESC NULLS FIRST"},
		{"group_display_name_asc", "display_name", "ascending", "ORDER BY display_name ASC NULLS LAST"},
		{"group_display_name_desc", "display_name", "descending", "ORDER BY display_name DESC NULLS FIRST"},
		{"emails_expression_asc", userSortEmailsExpression, "ascending", "ORDER BY " + userSortEmailsExpression + " ASC NULLS LAST"},
		{"emails_expression_desc", userSortEmailsExpression, "descending", "ORDER BY " + userSortEmailsExpression + " DESC NULLS FIRST"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildOrderClause(tc.col, tc.dir)
			if got != tc.want {
				t.Fatalf("buildOrderClause(%q, %q) = %q, want %q", tc.col, tc.dir, got, tc.want)
			}
		})
	}
}

// --- resolveGroupSortColumn ---

func TestResolveGroupSortColumn(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{"displayname", "display_name"},
		{"display_name", "display_name"},
		{"DISPLAYNAME", "display_name"},
		{"meta.created", "created_at"},
		{"meta.lastmodified", "last_modified"},
		{"externalid", "external_id"},
		{"", "display_name"},
		{"unknown_attr", "display_name"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := resolveGroupSortColumn(tc.input)
			if got != tc.want {
				t.Fatalf("resolveGroupSortColumn(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// --- marshalJSON ---

func TestMarshalJSON_Nil(t *testing.T) {
	t.Parallel()

	got := marshalJSON(nil)
	if got != nil {
		t.Fatalf("marshalJSON(nil) = %v, want nil", got)
	}
}

func TestMarshalJSON_EmptySlice(t *testing.T) {
	t.Parallel()

	got := marshalJSON([]model.ScimUserEmail{})
	// json.Marshal of empty slice produces "[]", not "null"
	if got == nil {
		t.Fatal("marshalJSON(empty slice) = nil, want non-nil")
	}
	if string(got) != "[]" {
		t.Fatalf("marshalJSON(empty slice) = %q, want \"[]\"", string(got))
	}
}

func TestMarshalJSON_ValidData(t *testing.T) {
	t.Parallel()

	emails := []model.ScimUserEmail{
		{Value: "alice@example.com", Type: "work", PrimaryFlag: true},
	}
	got := marshalJSON(emails)
	if got == nil {
		t.Fatal("marshalJSON(emails) = nil, want non-nil JSON")
	}
	if string(got) == "null" {
		t.Fatal("marshalJSON(emails) = \"null\", want JSON array")
	}
}

// --- unmarshalJSON ---

func TestUnmarshalJSON_Nil(t *testing.T) {
	t.Parallel()

	got := unmarshalJSON[model.ScimUserEmail](nil)
	if got != nil {
		t.Fatalf("unmarshalJSON(nil) = %v, want nil", got)
	}
}

func TestUnmarshalJSON_Empty(t *testing.T) {
	t.Parallel()

	got := unmarshalJSON[model.ScimUserEmail]([]byte{})
	if got != nil {
		t.Fatalf("unmarshalJSON(empty) = %v, want nil", got)
	}
}

func TestUnmarshalJSON_NullLiteral(t *testing.T) {
	t.Parallel()

	got := unmarshalJSON[model.ScimUserEmail]([]byte("null"))
	if got != nil {
		t.Fatalf("unmarshalJSON(\"null\") = %v, want nil", got)
	}
}

func TestUnmarshalJSON_ValidJSON(t *testing.T) {
	t.Parallel()

	data := []byte(`[{"value":"alice@example.com","type":"work","primaryFlag":true}]`)
	got := unmarshalJSON[model.ScimUserEmail](data)
	if len(got) != 1 {
		t.Fatalf("unmarshalJSON(valid) len = %d, want 1", len(got))
	}
	if got[0].Value != "alice@example.com" {
		t.Fatalf("unmarshalJSON(valid)[0].Value = %q, want alice@example.com", got[0].Value)
	}
	if !got[0].PrimaryFlag {
		t.Fatalf("unmarshalJSON(valid)[0].PrimaryFlag = false, want true")
	}
}

func TestUnmarshalJSON_InvalidJSON(t *testing.T) {
	t.Parallel()

	got := unmarshalJSON[model.ScimUserEmail]([]byte("not json"))
	if got != nil {
		t.Fatalf("unmarshalJSON(invalid JSON) = %v, want nil", got)
	}
}

func TestUnmarshalJSON_EmptyArray(t *testing.T) {
	t.Parallel()

	got := unmarshalJSON[model.ScimUserEmail]([]byte("[]"))
	// json.Unmarshal("[]") produces an empty non-nil slice
	if got == nil {
		t.Fatal("unmarshalJSON(\"[]\") = nil, want empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("unmarshalJSON(\"[]\") len = %d, want 0", len(got))
	}
}

// --- marshalJSON / unmarshalJSON round-trip ---

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	t.Parallel()

	roles := []model.ScimUserRole{
		{Value: "admin", Type: "direct", Display: "Administrator", PrimaryFlag: true},
		{Value: "viewer", Type: "indirect", Display: "Viewer"},
	}

	data := marshalJSON(roles)
	if data == nil {
		t.Fatal("marshalJSON returned nil for non-empty slice")
	}

	got := unmarshalJSON[model.ScimUserRole](data)
	if len(got) != 2 {
		t.Fatalf("round-trip len = %d, want 2", len(got))
	}
	if got[0].Value != "admin" || !got[0].PrimaryFlag {
		t.Fatalf("round-trip[0] = %+v, want {admin, true}", got[0])
	}
	if got[1].Value != "viewer" {
		t.Fatalf("round-trip[1].Value = %q, want viewer", got[1].Value)
	}
}

func TestReplaceCollectionEmails_Deduplication_USR22(t *testing.T) {
	t.Parallel()

	t.Run("nil or empty slice returns as-is", func(t *testing.T) {
		if replaceCollectionEmails(nil) != nil {
			t.Fatal("expected nil for nil input")
		}
		empty := []model.ScimUserEmail{}
		res := replaceCollectionEmails(empty)
		if len(res) != 0 {
			t.Fatalf("expected empty slice, got len %d", len(res))
		}
	})

	t.Run("single item returned as-is", func(t *testing.T) {
		single := []model.ScimUserEmail{
			{Value: "a@example.com", Type: "work"},
		}
		res := replaceCollectionEmails(single)
		if len(res) != 1 || res[0].Value != "a@example.com" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("duplicate (type, value) entries deduplicated", func(t *testing.T) {
		input := []model.ScimUserEmail{
			{Value: "dup@example.com", Type: "work"},
			{Value: "dup@example.com", Type: "work"},
			{Value: "other@example.com", Type: "home"},
		}
		res := replaceCollectionEmails(input)
		if len(res) != 2 {
			t.Fatalf("expected 2 emails after deduplication, got %d: %+v", len(res), res)
		}
		if res[0].Value != "dup@example.com" || res[0].Type != "work" {
			t.Errorf("res[0] = %+v, want dup@example.com", res[0])
		}
		if res[1].Value != "other@example.com" || res[1].Type != "home" {
			t.Errorf("res[1] = %+v, want other@example.com", res[1])
		}
	})

	t.Run("case-insensitive duplicate detection and whitespace trimming", func(t *testing.T) {
		input := []model.ScimUserEmail{
			{Value: "User@Example.Com ", Type: "WORK"},
			{Value: " user@example.com", Type: "work"},
		}
		res := replaceCollectionEmails(input)
		if len(res) != 1 {
			t.Fatalf("expected 1 email after case-insensitive deduplication, got %d: %+v", len(res), res)
		}
	})

	t.Run("primaryFlag preserved when duplicate has primaryFlag true", func(t *testing.T) {
		input := []model.ScimUserEmail{
			{Value: "dup@example.com", Type: "work", PrimaryFlag: false},
			{Value: "dup@example.com", Type: "work", PrimaryFlag: true},
		}
		res := replaceCollectionEmails(input)
		if len(res) != 1 {
			t.Fatalf("expected 1 email after deduplication, got %d", len(res))
		}
		if !res[0].PrimaryFlag {
			t.Errorf("expected primaryFlag to be preserved as true, got false")
		}
	})

	t.Run("distinct types with same value are retained", func(t *testing.T) {
		input := []model.ScimUserEmail{
			{Value: "common@example.com", Type: "work"},
			{Value: "common@example.com", Type: "home"},
		}
		res := replaceCollectionEmails(input)
		if len(res) != 2 {
			t.Fatalf("expected 2 emails with distinct types, got %d", len(res))
		}
	})
}

