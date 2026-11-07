package scim

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// CursorPrefix is the mandatory prefix for all RFC 9865 cursor tokens.
	CursorPrefix = "scim_cur_"

	// DefaultCursorTimeoutSeconds defines the default cursor validity duration (1 hour per RFC 9865 §4).
	DefaultCursorTimeoutSeconds = 3600
)

var (
	cursorSecretMu  sync.RWMutex
	cursorSecretKey = func() []byte {
		secret := os.Getenv("GO_CURSOR_SECRET")
		if secret == "" {
			secret = os.Getenv("SCIM_CURSOR_SECRET")
		}
		if secret != "" {
			sum := sha256.Sum256([]byte(secret))
			return sum[:]
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic("failed to generate random cursor HMAC secret: " + err.Error())
		}
		return key
	}()
)

// SetCursorSecret updates the HMAC secret key used for signing and verifying cursor tokens.
func SetCursorSecret(secret string) {
	if secret == "" {
		return
	}
	sum := sha256.Sum256([]byte(secret))
	cursorSecretMu.Lock()
	cursorSecretKey = sum[:]
	cursorSecretMu.Unlock()
}

func getCursorSecretKey() []byte {
	cursorSecretMu.RLock()
	defer cursorSecretMu.RUnlock()
	return cursorSecretKey
}

func computeCursorHMAC(wsID string, offset int, exp int64, pageSize int) string {
	mac := hmac.New(sha256.New, getCursorSecretKey())
	if pageSize > 0 {
		_, _ = fmt.Fprintf(mac, "%s|%d|%d|%d", wsID, offset, exp, pageSize)
	} else {
		_, _ = fmt.Fprintf(mac, "%s|%d|%d", wsID, offset, exp)
	}
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// CursorPayload represents the claims embedded inside the stateless opaque cursor token.
type CursorPayload struct {
	WorkspaceID string `json:"w"`
	Offset      *int   `json:"o"`
	ExpiresAt   *int64 `json:"exp"`
	PageSize    int    `json:"p,omitempty"`
	Sig         string `json:"s,omitempty"`
}

// EncodeCursor constructs a URL-safe unpadded Base64URL token prefixed with "scim_cur_".
func EncodeCursor(workspaceID uuid.UUID, offset int, timeoutSeconds int) (string, error) {
	return EncodeCursorWithPageSize(workspaceID, offset, 0, timeoutSeconds)
}

// EncodeCursorWithPageSize constructs a URL-safe unpadded Base64URL token prefixed with "scim_cur_",
// optionally embedding the page size used to produce the cursor.
func EncodeCursorWithPageSize(workspaceID uuid.UUID, offset int, pageSize int, timeoutSeconds int) (string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultCursorTimeoutSeconds
	}
	if offset < 0 {
		return "", NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: offset must be non-negative")
	}
	if pageSize < 0 {
		pageSize = 0
	}

	exp := time.Now().UTC().Add(time.Duration(timeoutSeconds) * time.Second).Unix()
	wsStr := workspaceID.String()
	payload := CursorPayload{
		WorkspaceID: wsStr,
		Offset:      &offset,
		ExpiresAt:   &exp,
		PageSize:    pageSize,
		Sig:         computeCursorHMAC(wsStr, offset, exp, pageSize),
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
	offset, _, err := DecodeCursorWithPageSize(token, workspaceID)
	return offset, err
}

// DecodeCursorWithPageSize validates and decodes the cursor token against the request workspace ID,
// returning both the offset and any embedded page size.
func DecodeCursorWithPageSize(token string, workspaceID uuid.UUID) (int, int, error) {
	if token == "" {
		return 0, 0, nil
	}

	if !strings.HasPrefix(token, CursorPrefix) {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: missing 'scim_cur_' prefix")
	}

	raw := strings.TrimPrefix(token, CursorPrefix)
	data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: malformed base64url encoding")
	}

	var p CursorPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: malformed payload JSON")
	}

	cursorWs, err := uuid.Parse(p.WorkspaceID)
	if err != nil || cursorWs != workspaceID {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Cursor does not belong to the target workspace")
	}

	if p.Offset == nil {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: missing offset parameter")
	}

	if p.ExpiresAt == nil {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: missing expiration timestamp")
	}

	if *p.Offset < 0 {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: negative offset")
	}

	if *p.ExpiresAt <= time.Now().UTC().Unix() {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Cursor has expired")
	}

	expectedSig := computeCursorHMAC(p.WorkspaceID, *p.Offset, *p.ExpiresAt, p.PageSize)
	if p.Sig == "" || !hmac.Equal([]byte(p.Sig), []byte(expectedSig)) {
		return 0, 0, NewScimError(http.StatusBadRequest, "invalidCursor", "Invalid cursor: integrity check failed")
	}

	return *p.Offset, p.PageSize, nil
}
