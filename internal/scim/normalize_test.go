package scim

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

func TestNormalizeUserInput_CaseInsensitiveAndCoreURNPrecedence(t *testing.T) {
	t.Parallel()

	mgrID := uuid.New().String()

	t.Run("PascalCase and URN-prefixed User attributes map identically across POST/PUT/PATCH", func(t *testing.T) {
		payloads := []map[string]any{
			{
				"UserName":          "bob",
				"Password":          "Valid!1",
				"DisplayName":       "Bob Builder",
				"ExternalId":        "ext-bob",
				"NickName":          "Bobby",
				"Title":             "Architect",
				"UserType":          "Employee",
				"PreferredLanguage": "en-US",
				"Locale":            "en_US",
				"Timezone":          "UTC",
				"Active":            false,
				"Name": map[string]any{
					"GivenName":       "Bob",
					"FamilyName":      "Builder",
					"Formatted":       "Mr. Bob Builder",
					"HonorificPrefix": "Mr.",
				},
				"Emails": []any{
					map[string]any{"Value": "BOB@EXAMPLE.COM", "Type": "WORK", "Primary": true, "Display": "Work Email"},
				},
				"Addresses": []any{
					map[string]any{"StreetAddress": "1 Main St", "Locality": "Austin", "Region": "TX", "PostalCode": "78701", "Country": "usa", "Type": "WORK", "Primary": true},
				},
				strings.ToUpper(EnterpriseSchemaURN): map[string]any{
					"EmployeeNumber": "E-42",
					"Department":     "Platform",
					"Manager": map[string]any{
						"Value": mgrID,
						"$REF":  "/Users/" + mgrID,
					},
				},
			},
			{
				UserSchemaURN + ":userName":    "bob",
				UserSchemaURN + ":password":    "Valid!1",
				UserSchemaURN + ":displayName": "Bob Builder",
				UserSchemaURN + ":externalId":  "ext-bob",
				UserSchemaURN: map[string]any{
					"nickName":          "Bobby",
					"title":             "Architect",
					"userType":          "Employee",
					"preferredLanguage": "en-US",
					"locale":            "en_US",
					"timezone":          "UTC",
					"active":            false,
					"name": map[string]any{
						"givenName":       "Bob",
						"familyName":      "Builder",
						"formatted":       "Mr. Bob Builder",
						"honorificPrefix": "Mr.",
					},
					"emails": []any{
						map[string]any{"value": "BOB@example.com", "type": "work", "primary": true, "display": "Work Email"},
					},
					"addresses": []any{
						map[string]any{"streetAddress": "1 Main St", "locality": "Austin", "region": "TX", "postalCode": "78701", "country": "US", "type": "work", "primary": true},
					},
				},
				EnterpriseSchemaURN + ":EmployeeNumber": "E-42",
				EnterpriseSchemaURN + ":Department":     "Platform",
				EnterpriseSchemaURN + ":Manager": map[string]any{
					"Value": mgrID,
					"$REF":  "/Users/" + mgrID,
				},
			},
		}

		for idx, p := range payloads {
			if err := ValidatePasswordInput(p); err != nil {
				t.Fatalf("payload %d: ValidatePasswordInput failed: %v", idx, err)
			}
			uPost := &model.ScimUser{}
			if err := ApplyFromScimInput(uPost, p); err != nil {
				t.Fatalf("payload %d: ApplyFromScimInput failed: %v", idx, err)
			}
			if uPost.UserName != "bob" || uPost.DisplayName == nil || *uPost.DisplayName != "Bob Builder" {
				t.Fatalf("payload %d: unexpected userName=%q displayName=%v", idx, uPost.UserName, uPost.DisplayName)
			}
			if uPost.Active {
				t.Fatalf("payload %d: expected Active=false", idx)
			}
			if uPost.Password == nil || bcrypt.CompareHashAndPassword([]byte(*uPost.Password), []byte("Valid!1")) != nil {
				t.Fatalf("payload %d: password not hashed properly", idx)
			}
			if uPost.NameGivenName == nil || *uPost.NameGivenName != "Bob" || uPost.NameFamilyName == nil || *uPost.NameFamilyName != "Builder" {
				t.Fatalf("payload %d: name sub-attributes not mapped", idx)
			}
			if len(uPost.Emails) != 1 || uPost.Emails[0].Value != "BOB@example.com" || !uPost.Emails[0].PrimaryFlag {
				t.Fatalf("payload %d: emails not mapped: %+v", idx, uPost.Emails)
			}
			if len(uPost.Addresses) != 1 || uPost.Addresses[0].StreetAddress != "1 Main St" || uPost.Addresses[0].Country != "US" {
				t.Fatalf("payload %d: addresses not mapped: %+v", idx, uPost.Addresses)
			}
			if uPost.EnterpriseEmployeeNumber == nil || *uPost.EnterpriseEmployeeNumber != "E-42" ||
				uPost.EnterpriseDepartment == nil || *uPost.EnterpriseDepartment != "Platform" ||
				uPost.EnterpriseManagerValue == nil || *uPost.EnterpriseManagerValue != mgrID {
				t.Fatalf("payload %d: enterprise extension not mapped", idx)
			}

			// Same payload in pathless PATCH replace produces identical state.
			uPatch := &model.ScimUser{UserName: "initial"}
			if err := ApplyPatchOperations(uPatch, []map[string]any{
				{"OP": "REPLACE", "VALUE": p},
			}); err != nil {
				t.Fatalf("payload %d: ApplyPatchOperations failed: %v", idx, err)
			}
			if uPatch.UserName != "bob" || uPatch.DisplayName == nil || *uPatch.DisplayName != "Bob Builder" ||
				uPatch.Password == nil || bcrypt.CompareHashAndPassword([]byte(*uPatch.Password), []byte("Valid!1")) != nil {
				t.Fatalf("payload %d: pathless PATCH state mismatch", idx)
			}
		}
	})

	t.Run("Deterministic 4-tier duplicate-key precedence across 100 iterations", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			// All 4 tiers present -> Tier 3 exact canonical ("displayName") wins.
			allTiers := map[string]any{
				"userName":                      "alice",
				"displayName":                   "Tier3Exact",
				"DisplayName":                   "Tier2Pascal",
				"DISPLAYNAME":                   "Tier2Upper",
				UserSchemaURN + ":displayName":  "Tier1URNExact",
				UserSchemaURN + ":DisplayName":  "Tier1URNPascal",
				UserSchemaURN: map[string]any{
					"displayName": "Tier0Nested",
				},
			}
			norm3 := NormalizeUserInput(allTiers)
			if norm3["displayName"] != "Tier3Exact" {
				t.Fatalf("iter %d: got %v, want Tier3Exact", i, norm3["displayName"])
			}

			// Tiers 2, 1, 0 -> Tier 2 lexically smallest ("DISPLAYNAME" < "DisplayName") wins.
			tier2 := map[string]any{
				"DisplayName":                  "Tier2Pascal",
				"DISPLAYNAME":                  "Tier2Upper",
				UserSchemaURN + ":displayName": "Tier1URN",
				UserSchemaURN: map[string]any{
					"displayName": "Tier0Nested",
				},
			}
			norm2 := NormalizeUserInput(tier2)
			if norm2["displayName"] != "Tier2Upper" {
				t.Fatalf("iter %d: got %v, want Tier2Upper", i, norm2["displayName"])
			}

			// Tiers 1, 0 -> Tier 1 lexically smallest wins over Tier 0.
			tier1 := map[string]any{
				UserSchemaURN + ":displayName": "Tier1Lower",
				UserSchemaURN + ":DisplayName": "Tier1PascalWinner",
				UserSchemaURN: map[string]any{
					"displayName": "Tier0Nested",
				},
			}
			norm1 := NormalizeUserInput(tier1)
			if norm1["displayName"] != "Tier1PascalWinner" {
				t.Fatalf("iter %d: got %v, want Tier1PascalWinner", i, norm1["displayName"])
			}

			// Tier 0 only -> exact canonical inner key beats case-variant inner key.
			tier0 := map[string]any{
				UserSchemaURN: map[string]any{
					"DISPLAYNAME": "Tier0UpperLoser",
					"displayName": "Tier0ExactWinner",
				},
			}
			norm0 := NormalizeUserInput(tier0)
			if norm0["displayName"] != "Tier0ExactWinner" {
				t.Fatalf("iter %d: got %v, want Tier0ExactWinner", i, norm0["displayName"])
			}
		}
	})

	t.Run("Group and PatchOp normalization", func(t *testing.T) {
		if NormalizeUserInput(nil) != nil || NormalizeGroupInput(nil) != nil {
			t.Fatal("nil maps must return nil")
		}
		memberID := uuid.New().String()
		gNorm := NormalizeGroupInput(map[string]any{
			"Schemas":     []string{GroupSchemaURN},
			"DisplayName": "Team Rocket",
			GroupSchemaURN: map[string]any{
				"displayName": "NestedLoser",
				"externalId":  "ext-grp-1",
			},
			"Members": []map[string]any{
				{"Value": memberID, "Type": "User", "$REF": "/Users/" + memberID, "Display": "Jessie"},
			},
		})
		if gNorm["displayName"] != "Team Rocket" || gNorm["externalId"] != "ext-grp-1" {
			t.Fatalf("unexpected normalized group: %+v", gNorm)
		}
		members, ok := gNorm["members"].([]map[string]any)
		if !ok || len(members) != 1 || members[0]["value"] != memberID || members[0]["$ref"] != "/Users/"+memberID {
			t.Fatalf("unexpected normalized group members: %#v", gNorm["members"])
		}

		reqNorm := NormalizePatchRequest(map[string]any{
			"SCHEMAS":    []any{patchOpSchemaURN},
			"operations": []any{map[string]any{"OP": "Replace", "PATH": "DisplayName", "VALUE": "New"}},
		})
		if _, ok := reqNorm["Operations"]; !ok {
			t.Fatalf("expected Operations key in %+v", reqNorm)
		}
	})
}

func TestValidatePatchOperationsPasswords(t *testing.T) {
	t.Parallel()

	validCases := [][]map[string]any{
		{{"op": "replace", "path": "displayName", "value": ""}},
		{{"op": "remove", "path": "password"}},
		{{"op": "replace", "path": "password", "value": "ValidSecret!1"}},
		{{"OP": "ADD", "PATH": UserSchemaURN + ":Password", "VALUE": "ValidSecret!1"}},
		{{"op": "add", "value": map[string]any{"password": "ValidSecret!1", "displayName": "Alice"}}},
		{nil},
	}
	for i, ops := range validCases {
		if err := ValidatePatchOperationsPasswords(ops); err != nil {
			t.Fatalf("valid case %d failed: %v", i, err)
		}
	}

	invalidCases := []struct {
		name string
		ops  []map[string]any
	}{
		{"empty password on replace", []map[string]any{{"op": "replace", "path": "password", "value": ""}}},
		{"whitespace password on replace", []map[string]any{{"op": "replace", "path": "password", "value": "   "}}},
		{"over 72 bytes", []map[string]any{{"op": "replace", "path": "password", "value": strings.Repeat("x", 100)}}},
		{"non-string password", []map[string]any{{"op": "replace", "path": "password", "value": 123}}},
		{"nil password value", []map[string]any{{"op": "replace", "path": "password", "value": nil}}},
		{"missing password value", []map[string]any{{"op": "replace", "path": "password"}}},
		{"empty op with invalid password", []map[string]any{{"path": "password", "value": ""}}},
		{"URN path empty password", []map[string]any{{"op": "replace", "path": UserSchemaURN + ":password", "value": ""}}},
		{"uppercase OP/PATH/VALUE", []map[string]any{{"OP": "ADD", "PATH": "PASSWORD", "VALUE": 123}}},
		{"pathless non-string password", []map[string]any{{"op": "add", "value": map[string]any{"password": 123}}}},
		{"pathless nil password", []map[string]any{{"op": "replace", "value": map[string]any{"password": nil}}}},
		{"pathless URN empty password", []map[string]any{{"op": "add", "value": map[string]any{UserSchemaURN + ":password": ""}}}},
		{"pathless nested core-URN invalid password", []map[string]any{{"op": "add", "value": map[string]any{UserSchemaURN: map[string]any{"Password": 123}}}}},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePatchOperationsPasswords(tc.ops)
			scimErr, ok := err.(*ScimError)
			if !ok || scimErr.Status != 400 || scimErr.ScimType != "invalidValue" {
				t.Fatalf("ValidatePatchOperationsPasswords(%s) = %T %v, want 400 invalidValue", tc.name, err, err)
			}
		})
	}
}

func TestNormalizeHelpersAndEdgeCases(t *testing.T) {
	t.Parallel()

	// StripGroupURNPrefix and StripCoreUserURNPrefix edge cases.
	if stripped, ok := StripGroupURNPrefix(strings.ToUpper(GroupSchemaURN) + ":DisplayName"); !ok || stripped != "DisplayName" {
		t.Fatalf("StripGroupURNPrefix got (%q, %v), want (\"DisplayName\", true)", stripped, ok)
	}
	if stripped, ok := StripGroupURNPrefix("displayName"); ok || stripped != "displayName" {
		t.Fatalf("StripGroupURNPrefix non-prefixed got (%q, %v)", stripped, ok)
	}
	if stripped, ok := StripCoreUserURNPrefix("userName"); ok || stripped != "userName" {
		t.Fatalf("StripCoreUserURNPrefix non-prefixed got (%q, %v)", stripped, ok)
	}

	// asciiEqualFold and asciiHasPrefixFold edge cases (length mismatch, uppercase b, non-ASCII 'ſ').
	if asciiEqualFold("abc", "ab") || asciiEqualFold("ab", "AC") || asciiEqualFold("pa\u017fsword", "password") {
		t.Fatal("asciiEqualFold returned true on unequal strings")
	}
	if !asciiEqualFold("abc", "ABC") || asciiHasPrefixFold("ab", "abc") {
		t.Fatal("asciiEqualFold / asciiHasPrefixFold basic assertion failed")
	}

	// normalizeObjectWithSchema(nil), nil core-URN value, non-map core-URN value, unknown inner key,
	// innerKey tie-break, non-map collection item, and non-slice collection value.
	if NormalizePatchRequest(nil) != nil {
		t.Fatal("NormalizePatchRequest(nil) must return nil")
	}
	edge := NormalizeUserInput(map[string]any{
		UserSchemaURN: nil,
		"emails":      []any{"not-a-map", map[string]any{"VALUE": "a@b.com"}},
		"roles":       "not-a-slice",
		"customattr":  "v1",
		EnterpriseSchemaURN: map[string]any{
			"Department": "ExplicitWins",
		},
		EnterpriseSchemaURN + ":DEPARTMENT": "FlatLoser1",
		EnterpriseSchemaURN + ":department": "FlatLoser2",
	})
	if edge["customattr"] != "v1" || edge["roles"] != "not-a-slice" {
		t.Fatalf("unexpected edge normalization: %+v", edge)
	}
	extMap, ok := edge[EnterpriseSchemaURN].(map[string]any)
	if !ok || extMap["department"] != "ExplicitWins" {
		t.Fatalf("explicit enterprise map should win over flat enterprise keys: %+v", edge[EnterpriseSchemaURN])
	}

	// Non-map value on UserSchemaURN preserved for downstream validation, plus Tier 0 innerKey tie-break.
	nonMapCore := NormalizeUserInput(map[string]any{
		UserSchemaURN: "invalid-non-object",
	})
	if nonMapCore[UserSchemaURN] != "invalid-non-object" {
		t.Fatalf("expected non-map core URN value preserved, got %+v", nonMapCore)
	}

	tier0Tie := NormalizeUserInput(map[string]any{
		UserSchemaURN: map[string]any{
			"DisplayName": "LoserPascal",
			"DISPLAYNAME": "WinnerUpper",
			"unknownattr": "kept",
		},
	})
	if tier0Tie["displayName"] != "WinnerUpper" || tier0Tie["unknownattr"] != "kept" {
		t.Fatalf("expected Tier 0 innerKey lexical tie-break WinnerUpper, got %+v", tier0Tie)
	}
}
