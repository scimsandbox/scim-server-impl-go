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
		{"name.givenname", "name_given_name"},
		{"displayname", "display_name"},
		{"title", "title"},
		{"emails.value", "emails"},
		{"email", "emails"},
		{"meta.created", "created_at"},
		{"meta.lastmodified", "last_modified"},
		{"externalid", "external_id"},
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
