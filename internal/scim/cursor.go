package scim

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// CursorPrefix is the mandatory prefix for all RFC 9865 cursor tokens.
	CursorPrefix = "scim_cur_"

	// DefaultCursorTimeoutSeconds defines the default cursor validity duration (1 hour per RFC 9865 §4).
	DefaultCursorTimeoutSeconds = 3600
)

// CursorPayload represents the claims embedded inside the stateless opaque cursor token.
type CursorPayload struct {
	WorkspaceID string `json:"w"`
	Offset      int    `json:"o"`
	ExpiresAt   int64  `json:"exp"`
}

// EncodeCursor constructs a URL-safe unpadded Base64URL token prefixed with "scim_cur_".
func EncodeCursor(workspaceID uuid.UUID, offset int, timeoutSeconds int) (string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultCursorTimeoutSeconds
	}
	if offset < 0 {
		return "", NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: offset must be non-negative")
	}

	exp := time.Now().UTC().Add(time.Duration(timeoutSeconds) * time.Second).Unix()
	payload := CursorPayload{
		WorkspaceID: workspaceID.String(),
		Offset:      offset,
		ExpiresAt:   exp,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return CursorPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeCursor validates and decodes the cursor token against the request workspace ID.
// Returns (0, nil) when token == "" per RFC 9865 §2 initial page specification.
// Returns *ScimError with Status 400 and ScimType "invalidCursor" on any validation failure.
func DecodeCursor(token string, workspaceID uuid.UUID) (int, error) {
	if token == "" {
		return 0, nil
	}

	if !strings.HasPrefix(token, CursorPrefix) {
		return 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: missing 'scim_cur_' prefix")
	}

	raw := strings.TrimPrefix(token, CursorPrefix)
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(raw)
	}
	if err != nil {
		return 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: malformed base64url encoding")
	}

	var p CursorPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: malformed payload JSON")
	}

	cursorWs, err := uuid.Parse(p.WorkspaceID)
	if err != nil || cursorWs != workspaceID {
		return 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Cursor does not belong to the target workspace")
	}

	if p.Offset < 0 {
		return 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: negative offset")
	}

	if p.ExpiresAt <= time.Now().UTC().Unix() {
		return 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Cursor has expired")
	}

	return p.Offset, nil
}
