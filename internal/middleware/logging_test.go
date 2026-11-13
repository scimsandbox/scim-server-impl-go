package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

type stubRequestLogCreator struct {
	logs []*model.ScimRequestLog
}

func (s *stubRequestLogCreator) Create(_ context.Context, log *model.ScimRequestLog) error {
	cp := *log
	s.logs = append(s.logs, &cp)
	return nil
}

// Traced RFC requirements (Group 1):
//   - RFC7643-9.2-287493: Password values MUST NOT be stored in cleartext form.
//   - RFC7643-4.1.1-6515f1: Locally held password values SHOULD be hashed.
//   - RFC7643-4.1.1-328207: Cleartext password set/changed by client SHOULD be processed securely.
//   - RFC7643-9.2-e4d59c: Protect credential storage.
//   - RFC7644-7.7-f11467: Protect credential storage.
func TestRedactSensitiveBody_PasswordRedaction_Group1(t *testing.T) {
	t.Run("top-level password in POST/PUT JSON", func(t *testing.T) {
		raw := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","displayName":"Alice","password":"TopSecret!Password1"}`
		got := RedactSensitiveBody(raw)
		if strings.Contains(got, "TopSecret!Password1") {
			t.Fatalf("cleartext password leaked in redacted JSON: %s", got)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(got), &m); err != nil {
			t.Fatalf("redacted output must remain valid JSON: %v (%s)", err, got)
		}
		if m["password"] != "[REDACTED]" {
			t.Errorf("password = %v, want [REDACTED]", m["password"])
		}
		if m["userName"] != "alice@example.com" || m["displayName"] != "Alice" {
			t.Errorf("non-password fields were mutated: %v", m)
		}
	})

	t.Run("case-insensitive Password and URN-prefixed password keys", func(t *testing.T) {
		raw := `{"userName":"bob@example.com","Password":"MixedCase!Secret2","urn:ietf:params:scim:schemas:core:2.0:User:Password":"UrnPrefixed!Secret3"}`
		got := RedactSensitiveBody(raw)
		if strings.Contains(got, "MixedCase!Secret2") || strings.Contains(got, "UrnPrefixed!Secret3") {
			t.Fatalf("cleartext password leaked: %s", got)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(got), &m); err != nil {
			t.Fatalf("unmarshal redacted JSON: %v", err)
		}
		if m["Password"] != "[REDACTED]" {
			t.Errorf("Password = %v, want [REDACTED]", m["Password"])
		}
		if m["urn:ietf:params:scim:schemas:core:2.0:User:Password"] != "[REDACTED]" {
			t.Errorf("URN Password = %v, want [REDACTED]", m["urn:ietf:params:scim:schemas:core:2.0:User:Password"])
		}
		if m["userName"] != "bob@example.com" {
			t.Errorf("userName = %v, want bob@example.com", m["userName"])
		}
	})

	t.Run("PATCH operations with path password and value map password", func(t *testing.T) {
		raw := `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[
				{"op":"replace","path":"password","value":"Secret!1"},
				{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:password","value":"Secret!1URN"},
				{"op":"add","value":{"password":"Secret!2","displayName":"KeepMe"}},
				{"op":"replace","path":"title","value":"Staff Engineer"}
			]
		}`
		got := RedactSensitiveBody(raw)
		for _, secret := range []string{"Secret!1", "Secret!1URN", "Secret!2"} {
			if strings.Contains(got, secret) {
				t.Fatalf("cleartext PATCH password %q leaked: %s", secret, got)
			}
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(got), &m); err != nil {
			t.Fatalf("unmarshal redacted PATCH JSON: %v", err)
		}
		ops, _ := m["Operations"].([]any)
		if len(ops) != 4 {
			t.Fatalf("len(Operations) = %d, want 4", len(ops))
		}
		if ops[0].(map[string]any)["value"] != "[REDACTED]" {
			t.Errorf("op[0].value = %v, want [REDACTED]", ops[0].(map[string]any)["value"])
		}
		if ops[1].(map[string]any)["value"] != "[REDACTED]" {
			t.Errorf("op[1].value = %v, want [REDACTED]", ops[1].(map[string]any)["value"])
		}
		op2Val := ops[2].(map[string]any)["value"].(map[string]any)
		if op2Val["password"] != "[REDACTED]" || op2Val["displayName"] != "KeepMe" {
			t.Errorf("op[2].value = %v, want password=[REDACTED] and displayName=KeepMe", op2Val)
		}
		if ops[3].(map[string]any)["value"] != "Staff Engineer" {
			t.Errorf("op[3].value = %v, want Staff Engineer", ops[3].(map[string]any)["value"])
		}
	})

	t.Run("BulkRequest containing POST and nested PATCH operations with passwords", func(t *testing.T) {
		raw := `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
			"Operations":[
				{
					"method":"POST",
					"path":"/Users",
					"bulkId":"u1",
					"data":{"userName":"bulk1@example.com","password":"BulkPost!Password4"}
				},
				{
					"method":"PATCH",
					"path":"/Users/1234",
					"data":{
						"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						"Operations":[
							{"op":"replace","path":"password","value":"BulkPatch!Password5"},
							{"op":"add","value":{"Password":"BulkPatchMap!Password6","nickName":"B"}}
						]
					}
				}
			]
		}`
		got := RedactSensitiveBody(raw)
		for _, secret := range []string{"BulkPost!Password4", "BulkPatch!Password5", "BulkPatchMap!Password6"} {
			if strings.Contains(got, secret) {
				t.Fatalf("cleartext Bulk password %q leaked: %s", secret, got)
			}
		}
		if !strings.Contains(got, "bulk1@example.com") || !strings.Contains(got, `"nickName":"B"`) {
			t.Errorf("expected non-password bulk fields preserved, got: %s", got)
		}
	})

	t.Run("malformed, non-JSON, and truncated JSON fallback redaction", func(t *testing.T) {
		cases := []struct {
			name   string
			input  string
			secret string
		}{
			{
				name:   "malformed JSON syntax",
				input:  `{"userName": "broken", "password": "Secret!3", trailing_garbage`,
				secret: "Secret!3",
			},
			{
				name:   "case-insensitive malformed JSON with escaped quote",
				input:  `not-json-at-all "Password" : "Sec\"ret!3b" & userName=alice`,
				secret: `Sec\"ret!3b`,
			},
			{
				name:   "truncated mid-password string",
				input:  `{"userName":"cut","password":"TruncatedSecret!4`,
				secret: "TruncatedSecret!4",
			},
			{
				name:   "malformed PATCH path-then-op-then-value unclosed object",
				input:  `{"Operations":[{"path":"password","op":"replace","value":"Secret!1"`,
				secret: "Secret!1",
			},
			{
				name:   "truncated PATCH path-then-op-then-value mid-string",
				input:  `{"Operations":[{"path":"password","op":"replace","value":"Secret!1CutMidString`,
				secret: "Secret!1CutMidString",
			},
			{
				name:   "malformed PATCH URN path-then-op-then-value mid-string",
				input:  `{"Operations":[{"path":"urn:ietf:params:scim:schemas:core:2.0:User:password","op":"add","value":"Secret!1UrnCut`,
				secret: "Secret!1UrnCut",
			},
			{
				name:   "malformed PATCH value-then-op-then-path unclosed object",
				input:  `{"Operations":[{"value":"Secret!2","op":"replace","path":"password"`,
				secret: "Secret!2",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := RedactSensitiveBody(tc.input)
				if strings.Contains(got, tc.secret) {
					t.Fatalf("secret %q leaked in malformed/truncated payload: %s", tc.secret, got)
				}
				if !strings.Contains(got, "[REDACTED]") {
					t.Fatalf("expected [REDACTED] marker in output: %s", got)
				}
			})
		}

		// Also verify cross-object boundary safety: non-password sibling operation value is preserved.
		mixedMalformed := `{"Operations":[{"value":"KeepTitle","path":"title"},{"value":"Secret!CrossCheck","op":"replace","path":"password"`
		gotMixed := RedactSensitiveBody(mixedMalformed)
		if strings.Contains(gotMixed, "Secret!CrossCheck") {
			t.Fatalf("password secret leaked in mixed malformed PATCH: %s", gotMixed)
		}
		if !strings.Contains(gotMixed, "KeepTitle") {
			t.Fatalf("expected sibling operation value 'KeepTitle' preserved across {} boundary, got: %s", gotMixed)
		}
	})
}

// RFC7643-9.2-287493 / RFC7643-4.1.1-328207 / RFC7643-9.2-e4d59c / RFC7644-7.7-f11467:
// Ensures RequestResponseLogging redacts persisted logs while passing the exact unmutated
// request stream downstream to SCIM handlers.
func TestRequestResponseLogging_RedactsLogWithoutMutatingDownstreamRequestBody(t *testing.T) {
	wsID := uuid.New()
	rawCleartext := "CleartextDownstream!99"
	reqJSON := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"stream@example.com","password":"` + rawCleartext + `"}`

	logStore := &stubRequestLogCreator{}
	var downstreamSeenPassword string

	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("downstream read body: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			t.Fatalf("downstream unmarshal: %v", err)
		}
		downstreamSeenPassword, _ = payload["password"].(string)

		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"11111111-1111-1111-1111-111111111111","userName":"stream@example.com"}`))
	})

	mw := RequestResponseLogging(logStore)(downstream)
	req := httptest.NewRequest(http.MethodPost, "/ws/"+wsID.String()+"/scim/v2/Users", bytes.NewBufferString(reqJSON))
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if downstreamSeenPassword != rawCleartext {
		t.Fatalf("downstream handler received password %q, want untouched cleartext %q", downstreamSeenPassword, rawCleartext)
	}
	if len(logStore.logs) != 1 {
		t.Fatalf("saved logs = %d, want 1", len(logStore.logs))
	}
	saved := logStore.logs[0]
	if saved.WorkspaceID != wsID {
		t.Errorf("saved WorkspaceID = %s, want %s", saved.WorkspaceID, wsID)
	}
	if saved.RequestBody == nil {
		t.Fatal("expected non-nil RequestBody in saved log")
	}
	if strings.Contains(*saved.RequestBody, rawCleartext) {
		t.Fatalf("cleartext password leaked into scim_request_logs.request_body: %s", *saved.RequestBody)
	}
	if !strings.Contains(*saved.RequestBody, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in RequestBody, got: %s", *saved.RequestBody)
	}
}

type countingInfiniteReader struct {
	bytesRead int64
}

func (c *countingInfiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	c.bytesRead += int64(len(p))
	return len(p), nil
}

func TestRequestResponseLogging_DoesNotPreReadUnboundedStreamBeforeMaxBytesReader(t *testing.T) {
	wsID := uuid.New()
	logStore := &stubRequestLogCreator{}
	stream := &countingInfiniteReader{}

	const maxLimit = 1048576 // 1 MiB
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxLimit)
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Fatal("expected MaxBytesReader error on unbounded stream")
		}
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"status":"413"}`))
	})

	mw := RequestResponseLogging(logStore)(downstream)
	req := httptest.NewRequest(http.MethodPost, "/ws/"+wsID.String()+"/scim/v2/Bulk", io.NopCloser(stream))
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	// Stream must have been stopped around 1 MiB (+ small read buffer), never pre-read unboundedly
	if stream.bytesRead > maxLimit+65536 {
		t.Fatalf("stream read %d bytes, expected <= %d", stream.bytesRead, maxLimit+65536)
	}
	if len(logStore.logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logStore.logs))
	}
	if logStore.logs[0].RequestBody == nil || len(*logStore.logs[0].RequestBody) > maxBodyLog+64 {
		t.Fatalf("logged request body exceeded maxBodyLog truncation limit")
	}
}

func TestRequestResponseLogging_NeverLogsAuthHeaderAndRedactsAuthorizationInBody(t *testing.T) {
	wsID := uuid.New()
	logStore := &stubRequestLogCreator{}
	bearerSecret := "super-secret-bearer-token-xyz123"
	bodyAuthSecret := "Bearer body-embedded-token-abc987"
	reqJSON := `{"userName":"alice@example.com","Authorization":"` + bodyAuthSecret + `","password":"SecretPassword!1"}`

	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"11111111-1111-1111-1111-111111111111"}`))
	})

	mw := RequestResponseLogging(logStore)(downstream)
	req := httptest.NewRequest(http.MethodPost, "/ws/"+wsID.String()+"/scim/v2/Users", bytes.NewBufferString(reqJSON))
	req.Header.Set("Authorization", "Bearer "+bearerSecret)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if len(logStore.logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logStore.logs))
	}
	saved := logStore.logs[0]
	if saved.RequestBody == nil {
		t.Fatal("expected non-nil RequestBody")
	}
	for _, secret := range []string{bearerSecret, "body-embedded-token-abc987", "SecretPassword!1"} {
		if strings.Contains(*saved.RequestBody, secret) {
			t.Fatalf("secret %q leaked into RequestBody: %s", secret, *saved.RequestBody)
		}
	}

	// Verify standalone Bearer token and truncated Authorization field fallback redaction.
	rawBearer := RedactSensitiveBody(`{"detail":"upstream header Bearer secret-jwt-999999"}`)
	if strings.Contains(rawBearer, "secret-jwt-999999") || !strings.Contains(rawBearer, "Bearer [REDACTED]") {
		t.Fatalf("expected inline Bearer token to be redacted, got: %s", rawBearer)
	}
	truncAuth := RedactSensitiveBody(`{"Authorization":"Bearer cut-off-secret`)
	if strings.Contains(truncAuth, "cut-off-secret") || !strings.Contains(truncAuth, "[REDACTED]") {
		t.Fatalf("expected truncated Authorization value to be redacted, got: %s", truncAuth)
	}
}
