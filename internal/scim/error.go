package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ScimError represents a SCIM protocol error.
type ScimError struct {
	Status  int    `json:"-"`
	ScimType string `json:"scimType,omitempty"`
	Detail  string `json:"detail"`
}

func (e *ScimError) Error() string {
	return fmt.Sprintf("SCIM error %d: %s", e.Status, e.Detail)
}

func NewScimError(status int, scimType, detail string) *ScimError {
	return &ScimError{Status: status, ScimType: scimType, Detail: detail}
}

// WriteScimError writes a SCIM error response.
func WriteScimError(w http.ResponseWriter, err *ScimError) {
	body := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  fmt.Sprintf("%d", err.Status),
		"detail":  err.Detail,
	}
	if err.ScimType != "" {
		body["scimType"] = err.ScimType
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(err.Status)
	json.NewEncoder(w).Encode(body)
}

// WriteErrorFromAny handles both *ScimError and generic errors.
func WriteErrorFromAny(w http.ResponseWriter, err error) {
	if scimErr, ok := err.(*ScimError); ok {
		WriteScimError(w, scimErr)
		return
	}
	WriteScimError(w, &ScimError{Status: 500, Detail: "Internal server error"})
}
