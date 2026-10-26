package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

// isAsyncPreferred checks if the request contains 'Prefer: respond-async' per RFC 7240.
func isAsyncPreferred(r *http.Request) bool {
	if r == nil {
		return false
	}
	for _, val := range r.Header.Values("Prefer") {
		for _, part := range strings.Split(val, ",") {
			token := strings.TrimSpace(strings.Split(part, ";")[0])
			if strings.EqualFold(token, "respond-async") {
				return true
			}
		}
	}
	return false
}

// buildSETJson constructs an RFC 8417 / RFC 9967 Security Event Token (SET) JSON payload.
func buildSETJson(
	baseURL string,
	txnID uuid.UUID,
	resourceType string,
	resourceID uuid.UUID,
	method string,
	resourceMap map[string]any,
) (string, error) {
	var eventURN string
	switch strings.ToUpper(method) {
	case "POST":
		eventURN = "urn:ietf:params:scim:event:prov:create:full"
	case "PUT":
		eventURN = "urn:ietf:params:scim:event:prov:put:full"
	case "PATCH":
		eventURN = "urn:ietf:params:scim:event:prov:patch:full"
	case "DELETE":
		eventURN = "urn:ietf:params:scim:event:prov:delete:full"
	default:
		eventURN = "urn:ietf:params:scim:event:prov:create:full"
	}

	plural := "Users"
	if strings.EqualFold(resourceType, "group") {
		plural = "Groups"
	}
	resourceURI := baseURL + "/" + plural + "/" + resourceID.String()

	eventPayload := map[string]any{}
	if resourceMap != nil && strings.ToUpper(method) != "DELETE" {
		eventPayload["attributes"] = resourceMap
	}

	payload := map[string]any{
		"iss": baseURL,
		"iat": time.Now().UTC().Unix(),
		"jti": uuid.New().String(),
		"txn": txnID.String(),
		"sub_id": map[string]any{
			"format": "uri",
			"uri":    resourceURI,
		},
		"events": map[string]any{
			eventURN: eventPayload,
		},
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// AsyncEventHandler handles polling retrieval of RFC 9967 Security Event Tokens.
type AsyncEventHandler struct {
	repo repository.AsyncEventRepo
}

// NewAsyncEventHandler creates an AsyncEventHandler.
func NewAsyncEventHandler(repo repository.AsyncEventRepo) *AsyncEventHandler {
	return &AsyncEventHandler{repo: repo}
}

// GetEvent handles GET /Events/{txnId}.
func (h *AsyncEventHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	txnIDStr := chi.URLParam(r, "txnId")
	txnID, err := uuid.Parse(txnIDStr)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Invalid event transaction ID"))
		return
	}

	event, err := h.repo.FindByTxnIDAndWorkspaceID(r.Context(), txnID, wsID)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to retrieve event"))
		return
	}
	if event == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", fmt.Sprintf("Event with txnId '%s' not found", txnIDStr)))
		return
	}

	baseURL := buildBaseURL(r)
	eventURL := baseURL + "/Events/" + txnID.String()

	switch event.Status {
	case model.AsyncStatusPending:
		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)
		return

	case model.AsyncStatusCompleted:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if event.SetPayload != nil {
			_, _ = w.Write([]byte(*event.SetPayload))
		}
		return

	case model.AsyncStatusFailed:
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Asynchronous operation failed"))
		return

	default:
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Unknown event status"))
		return
	}
}
