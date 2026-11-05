package scim

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEncodeDecodeCursor_RoundTrip(t *testing.T) {
	wsID := uuid.New()
	testOffsets := []int{0, 1, 10, 25, 100, 9999}

	for _, offset := range testOffsets {
		token, err := EncodeCursor(wsID, offset, 3600)
		if err != nil {
			t.Fatalf("unexpected error encoding cursor: %v", err)
		}

		if !strings.HasPrefix(token, CursorPrefix) {
			t.Fatalf("expected token to have prefix %q, got %q", CursorPrefix, token)
		}

		decodedOffset, err := DecodeCursor(token, wsID)
		if err != nil {
			t.Fatalf("unexpected error decoding cursor: %v", err)
		}

		if decodedOffset != offset {
			t.Fatalf("expected offset %d, got %d", offset, decodedOffset)
		}
	}
}

func TestDecodeCursor_EmptyString(t *testing.T) {
	wsID := uuid.New()
	offset, err := DecodeCursor("", wsID)
	if err != nil {
		t.Fatalf("expected nil error for empty cursor, got: %v", err)
	}
	if offset != 0 {
		t.Fatalf("expected offset 0 for empty cursor, got: %d", offset)
	}
}

func TestDecodeCursor_InvalidPrefix(t *testing.T) {
	wsID := uuid.New()
	invalidTokens := []string{
		"invalid-token",
		"scim_cursor_xyz",
		"cur_12345",
		"Bearer xyz",
	}

	for _, token := range invalidTokens {
		_, err := DecodeCursor(token, wsID)
		if err == nil {
			t.Fatalf("expected error for token %q, got nil", token)
		}
		scimErr, ok := err.(*ScimError)
		if !ok {
			t.Fatalf("expected *ScimError, got %T", err)
		}
		if scimErr.Status != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", scimErr.Status, http.StatusBadRequest)
		}
		if scimErr.ScimType != "invalidCursor" {
			t.Errorf("scimType = %q, want invalidCursor", scimErr.ScimType)
		}
	}
}

func TestDecodeCursor_InvalidBase64(t *testing.T) {
	wsID := uuid.New()
	token := CursorPrefix + "!!!not-valid-base64-url???"
	_, err := DecodeCursor(token, wsID)
	if err == nil {
		t.Fatalf("expected error for malformed base64, got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
}

func TestDecodeCursor_InvalidJSON(t *testing.T) {
	wsID := uuid.New()
	malformedPayload := base64.RawURLEncoding.EncodeToString([]byte("not valid json"))
	token := CursorPrefix + malformedPayload

	_, err := DecodeCursor(token, wsID)
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
}

func TestDecodeCursor_WorkspaceMismatch(t *testing.T) {
	wsA := uuid.New()
	wsB := uuid.New()

	token, err := EncodeCursor(wsA, 10, 3600)
	if err != nil {
		t.Fatalf("unexpected encode error: %v", err)
	}

	_, err = DecodeCursor(token, wsB)
	if err == nil {
		t.Fatalf("expected error when decoding with wrong workspace ID, got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
}

func TestDecodeCursor_NegativeOffset(t *testing.T) {
	wsID := uuid.New()
	negOffset := -5
	futureExp := time.Now().UTC().Add(time.Hour).Unix()
	payload := CursorPayload{
		WorkspaceID: wsID.String(),
		Offset:      &negOffset,
		ExpiresAt:   &futureExp,
	}
	data, _ := json.Marshal(payload)
	token := CursorPrefix + base64.RawURLEncoding.EncodeToString(data)

	_, err := DecodeCursor(token, wsID)
	if err == nil {
		t.Fatalf("expected error for negative offset, got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
}

func TestDecodeCursor_Expired(t *testing.T) {
	wsID := uuid.New()
	offset := 5
	pastExp := time.Now().UTC().Add(-10 * time.Minute).Unix()
	payload := CursorPayload{
		WorkspaceID: wsID.String(),
		Offset:      &offset,
		ExpiresAt:   &pastExp,
	}
	data, _ := json.Marshal(payload)
	token := CursorPrefix + base64.RawURLEncoding.EncodeToString(data)

	_, err := DecodeCursor(token, wsID)
	if err == nil {
		t.Fatalf("expected error for expired cursor, got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
}

func TestEncodeCursor_NegativeOffsetFails(t *testing.T) {
	wsID := uuid.New()
	_, err := EncodeCursor(wsID, -1, 3600)
	if err == nil {
		t.Fatalf("expected error encoding negative offset, got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
}

func TestDecodeCursor_MissingOffset(t *testing.T) {
	wsID := uuid.New()
	futureExp := time.Now().UTC().Add(time.Hour).Unix()
	rawJSON := fmt.Sprintf(`{"w":"%s","exp":%d}`, wsID, futureExp)
	token := CursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(rawJSON))

	_, err := DecodeCursor(token, wsID)
	if err == nil {
		t.Fatalf("expected error for missing offset 'o', got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
	if !strings.Contains(scimErr.Detail, "missing offset parameter") {
		t.Errorf("detail = %q, want 'missing offset parameter'", scimErr.Detail)
	}
}

func TestDecodeCursor_MissingExpiresAt(t *testing.T) {
	wsID := uuid.New()
	rawJSON := fmt.Sprintf(`{"w":"%s","o":10}`, wsID)
	token := CursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(rawJSON))

	_, err := DecodeCursor(token, wsID)
	if err == nil {
		t.Fatalf("expected error for missing expiration 'exp', got nil")
	}
	scimErr, ok := err.(*ScimError)
	if !ok || scimErr.Status != http.StatusBadRequest || scimErr.ScimType != "invalidCursor" {
		t.Fatalf("expected 400 invalidCursor, got: %v", err)
	}
	if !strings.Contains(scimErr.Detail, "missing expiration timestamp") {
		t.Errorf("detail = %q, want 'missing expiration timestamp'", scimErr.Detail)
	}
}

func TestDecodeCursor_TamperAndStrictBase64Detection(t *testing.T) {
	wsID := uuid.New()
	token, err := EncodeCursor(wsID, 1, 3600)
	if err != nil {
		t.Fatalf("EncodeCursor failed: %v", err)
	}

	// Flip the very last character (e.g., 'Q' <-> 'a'), which in non-strict base64url
	// could only affect unused trailing bits if Strict() + HMAC were not enforced.
	last := token[len(token)-1]
	replacement := byte('a')
	if last == 'a' {
		replacement = 'b'
	}
	tampered := token[:len(token)-1] + string(replacement)
	if _, err := DecodeCursor(tampered, wsID); err == nil {
		t.Fatalf("expected tampered cursor %q (from %q) to be rejected", tampered, token)
	}

	// Forge a syntactically valid unsigned JSON payload with matching workspace, valid offset, and future exp
	offset := 2
	futureExp := time.Now().UTC().Add(time.Hour).Unix()
	unsignedJSON := fmt.Sprintf(`{"w":"%s","o":%d,"exp":%d}`, wsID.String(), offset, futureExp)
	forged := CursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(unsignedJSON))
	if _, err := DecodeCursor(forged, wsID); err == nil {
		t.Fatal("expected forged unsigned cursor to fail HMAC integrity check")
	}
}

