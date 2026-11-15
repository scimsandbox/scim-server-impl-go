package repository

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
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
// Updated per RFC 7644 §3.4.2.3: string attributes with caseExact:false sort via LOWER(col)
// with deterministic COLLATE "C" and id tie-breakers, while caseExact:true attributes use COLLATE "C".

func TestBuildOrderClause(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		col  string
		dir  string
		want string
	}{
		{"default_ascending", "user_name", "", `ORDER BY LOWER(user_name) ASC NULLS LAST, user_name COLLATE "C" ASC NULLS LAST, id ASC`},
		{"explicit_asc", "user_name", "ASC", `ORDER BY LOWER(user_name) ASC NULLS LAST, user_name COLLATE "C" ASC NULLS LAST, id ASC`},
		{"lowercase_asc", "user_name", "asc", `ORDER BY LOWER(user_name) ASC NULLS LAST, user_name COLLATE "C" ASC NULLS LAST, id ASC`},
		{"full_ascending", "user_name", "ascending", `ORDER BY LOWER(user_name) ASC NULLS LAST, user_name COLLATE "C" ASC NULLS LAST, id ASC`},
		{"explicit_desc", "user_name", "DESC", `ORDER BY LOWER(user_name) DESC NULLS FIRST, user_name COLLATE "C" DESC NULLS FIRST, id ASC`},
		{"lowercase_desc", "user_name", "desc", `ORDER BY LOWER(user_name) DESC NULLS FIRST, user_name COLLATE "C" DESC NULLS FIRST, id ASC`},
		{"full_descending", "user_name", "descending", `ORDER BY LOWER(user_name) DESC NULLS FIRST, user_name COLLATE "C" DESC NULLS FIRST, id ASC`},
		{"mixed_case_descending", "user_name", "Descending", `ORDER BY LOWER(user_name) DESC NULLS FIRST, user_name COLLATE "C" DESC NULLS FIRST, id ASC`},
		{"group_display_name_asc", "display_name", "ascending", `ORDER BY LOWER(display_name) ASC NULLS LAST, display_name COLLATE "C" ASC NULLS LAST, id ASC`},
		{"group_display_name_desc", "display_name", "descending", `ORDER BY LOWER(display_name) DESC NULLS FIRST, display_name COLLATE "C" DESC NULLS FIRST, id ASC`},
		{"emails_expression_asc", userSortEmailsExpression, "ascending", "ORDER BY LOWER(" + userSortEmailsExpression + ") ASC NULLS LAST, id ASC"},
		{"emails_expression_desc", userSortEmailsExpression, "descending", "ORDER BY LOWER(" + userSortEmailsExpression + ") DESC NULLS FIRST, id ASC"},
		{"case_exact_external_id_asc", "external_id", "ascending", `ORDER BY external_id COLLATE "C" ASC NULLS LAST, id ASC`},
		{"case_exact_id_desc", "id", "descending", `ORDER BY id::text COLLATE "C" DESC`},
		{"non_string_created_at_asc", "created_at", "ascending", `ORDER BY created_at ASC NULLS LAST, id ASC`},
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

type stubBoolRow struct {
	val bool
	err error
}

func (r stubBoolRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) > 0 {
		if ptr, ok := dest[0].(*bool); ok {
			*ptr = r.val
		}
	}
	return nil
}

type stubCycleExecutor struct {
	lastQuery string
	lastArgs  []any
	row       stubBoolRow
}

func (e *stubCycleExecutor) ExecContext(_ context.Context, _ string, _ ...any) (jdbc.Result, error) {
	return nil, nil
}

func (e *stubCycleExecutor) QueryContext(_ context.Context, _ string, _ ...any) (jdbc.Rows, error) {
	return nil, nil
}

func (e *stubCycleExecutor) QueryRowContext(_ context.Context, query string, args ...any) jdbc.Row {
	e.lastQuery = query
	e.lastArgs = args
	return e.row
}

func TestMembershipRepository_CreatesGroupCycleTx(t *testing.T) {
	t.Parallel()

	repo := NewMembershipRepository()
	wsID := uuid.New()
	groupA := uuid.New()
	groupB := uuid.New()

	// 1. Self-membership short-circuits without hitting the executor.
	txNever := &stubCycleExecutor{row: stubBoolRow{err: errors.New("should not query DB on self-membership")}}
	cycle, err := repo.CreatesGroupCycleTx(context.Background(), txNever, wsID, groupA, groupA)
	if err != nil || !cycle {
		t.Fatalf("CreatesGroupCycleTx(self) = (%v, %v), want (true, nil)", cycle, err)
	}
	if txNever.lastQuery != "" {
		t.Fatal("expected self-membership to return true before querying DB")
	}

	cycleNoTx, err := repo.CreatesGroupCycle(context.Background(), wsID, groupA, groupA)
	if err != nil || !cycleNoTx {
		t.Fatalf("CreatesGroupCycle(self) = (%v, %v), want (true, nil)", cycleNoTx, err)
	}

	// 2. Transitive cycle detected via recursive CTE.
	txTrue := &stubCycleExecutor{row: stubBoolRow{val: true}}
	cycle, err = repo.CreatesGroupCycleTx(context.Background(), txTrue, wsID, groupA, groupB)
	if err != nil || !cycle {
		t.Fatalf("CreatesGroupCycleTx(cycle) = (%v, %v), want (true, nil)", cycle, err)
	}
	if !strings.Contains(txTrue.lastQuery, "WITH RECURSIVE reachable") || !strings.Contains(txTrue.lastQuery, "UNION") {
		t.Fatalf("expected deduplicated WITH RECURSIVE UNION query, got: %s", txTrue.lastQuery)
	}
	if len(txTrue.lastArgs) != 3 || txTrue.lastArgs[0] != wsID || txTrue.lastArgs[1] != groupB || txTrue.lastArgs[2] != groupA {
		t.Fatalf("unexpected query args: %+v", txTrue.lastArgs)
	}

	// 3. Acyclic DAG returns false.
	txFalse := &stubCycleExecutor{row: stubBoolRow{val: false}}
	cycle, err = repo.CreatesGroupCycleTx(context.Background(), txFalse, wsID, groupA, groupB)
	if err != nil || cycle {
		t.Fatalf("CreatesGroupCycleTx(acyclic) = (%v, %v), want (false, nil)", cycle, err)
	}

	// 4. DB error propagates cleanly.
	wantErr := errors.New("db failure")
	txErr := &stubCycleExecutor{row: stubBoolRow{err: wantErr}}
	if _, err := repo.CreatesGroupCycleTx(context.Background(), txErr, wsID, groupA, groupB); !errors.Is(err, wantErr) {
		t.Fatalf("CreatesGroupCycleTx(err) = %v, want %v", err, wantErr)
	}
}

