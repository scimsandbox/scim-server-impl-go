package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

const (
	AsyncRespEventURN  = "urn:ietf:params:scim:event:misc:asyncresp"
	ProvCreateFullURN  = "urn:ietf:params:scim:event:prov:create:full"
	ProvPutFullURN     = "urn:ietf:params:scim:event:prov:put:full"
	ProvPatchNoticeURN = "urn:ietf:params:scim:event:prov:patch:notice"
	ProvDeleteURN      = "urn:ietf:params:scim:event:prov:delete"

	maxConcurrentAsyncWorkers = 64
)

var asyncWorkerSem = make(chan struct{}, maxConcurrentAsyncWorkers)

func runAsyncWorker(
	repo repository.AsyncEventRepo,
	baseURL string,
	txnID uuid.UUID,
	resourceType string,
	initialResID *uuid.UUID,
	method string,
	op func(ctx context.Context) (resID *uuid.UUID, setJSON string, err error),
) {
	go func() {
		asyncWorkerSem <- struct{}{}
		defer func() { <-asyncWorkerSem }()

		recordFailure := func(resID *uuid.UUID, opErr error) {
			if resID == nil {
				resID = initialResID
			}
			statusCtx, statusCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer statusCancel()
			errSet, _ := buildErrorSETJson(baseURL, txnID, resourceType, resID, method, opErr)
			_ = repo.UpdateStatusAndPayload(statusCtx, txnID, model.AsyncStatusFailed, resID, &errSet, time.Now().UTC())
		}

		defer func() {
			if r := recover(); r != nil {
				slog.Error("panic in async SCIM worker", "txnId", txnID, "resourceType", resourceType, "method", method, "panic", r)
				recordFailure(initialResID, scim.NewScimError(http.StatusInternalServerError, "", "Internal server error"))
			}
		}()

		workerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		resID, setJSON, err := op(workerCtx)
		if err != nil {
			recordFailure(resID, err)
			return
		}

		statusCtx, statusCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer statusCancel()
		_ = repo.UpdateStatusAndPayload(statusCtx, txnID, model.AsyncStatusCompleted, resID, &setJSON, time.Now().UTC())
	}()
}

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

// parseWaitPreference extracts the RFC 7240 'wait=N' preference value in seconds if present.
func parseWaitPreference(r *http.Request) (int, bool) {
	if r == nil {
		return 0, false
	}
	for _, val := range r.Header.Values("Prefer") {
		for _, commaPart := range strings.Split(val, ",") {
			for _, semiPart := range strings.Split(commaPart, ";") {
				seg := strings.TrimSpace(semiPart)
				eqIdx := strings.IndexByte(seg, '=')
				if eqIdx <= 0 {
					continue
				}
				k := strings.TrimSpace(seg[:eqIdx])
				v := strings.Trim(strings.TrimSpace(seg[eqIdx+1:]), `"`)
				if strings.EqualFold(k, "wait") {
					if n, err := strconv.Atoi(v); err == nil && n >= 0 {
						return n, true
					}
				}
			}
		}
	}
	return 0, false
}

// shouldExecuteAsync determines whether to dispatch asynchronously (202 Accepted) or execute
// synchronously within the client's RFC 7240 'wait' budget (RFC 9967 §2.5.1.1).
func shouldExecuteAsync(r *http.Request) (bool, string) {
	if !isAsyncPreferred(r) {
		return false, ""
	}
	if waitSec, hasWait := parseWaitPreference(r); hasWait {
		if waitSec > 0 {
			return false, ""
		}
		return true, "respond-async, wait=0"
	}
	return true, "respond-async"
}

// extractModifiedPatchPaths extracts RFC 7644 §3.5.2 attrPath names from PATCH operations
// for inclusion in RFC 9967 'urn:ietf:params:scim:event:prov:patch:notice' events.
func extractModifiedPatchPaths(operations []map[string]any) []string {
	seen := make(map[string]bool)
	var paths []string
	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for _, op := range operations {
		rawPath, _ := op["path"].(string)
		trimmedPath := strings.TrimSpace(rawPath)
		if trimmedPath != "" {
			if strings.EqualFold(trimmedPath, scim.EnterpriseSchemaURN) {
				if valMap, ok := op["value"].(map[string]any); ok && len(valMap) > 0 {
					for subK := range valMap {
						addPath(scim.EnterpriseSchemaURN + ":" + subK)
					}
					continue
				}
			}
			addPath(trimmedPath)
			continue
		}
		if valMap, ok := op["value"].(map[string]any); ok {
			for k, v := range valMap {
				if strings.EqualFold(k, "schemas") {
					continue
				}
				if strings.EqualFold(k, scim.EnterpriseSchemaURN) {
					if entMap, ok := v.(map[string]any); ok && len(entMap) > 0 {
						for subK := range entMap {
							addPath(scim.EnterpriseSchemaURN + ":" + subK)
						}
						continue
					}
				}
				addPath(k)
			}
		}
	}
	if len(paths) == 0 {
		paths = []string{"displayName"}
	}
	return paths
}

// buildSETJson constructs an RFC 8417 / RFC 9967 Security Event Token (SET) JSON payload
// for a completed asynchronous SCIM request.
func buildSETJson(
	baseURL string,
	txnID uuid.UUID,
	resourceType string,
	resourceID uuid.UUID,
	method string,
	resourceMap map[string]any,
	patchPaths ...string,
) (string, error) {
	upperMethod := strings.ToUpper(method)
	plural := "Users"
	if strings.EqualFold(resourceType, "group") {
		plural = "Groups"
	}
	resourceURI := baseURL + "/" + plural + "/" + resourceID.String()

	asyncRespPayload := map[string]any{
		"method":   upperMethod,
		"location": resourceURI,
	}

	var provURN string
	provPayload := map[string]any{}

	switch upperMethod {
	case "POST":
		asyncRespPayload["status"] = "201"
		if resourceMap != nil {
			asyncRespPayload["response"] = resourceMap
			provPayload["data"] = resourceMap
		}
		provURN = ProvCreateFullURN
	case "PUT":
		asyncRespPayload["status"] = "200"
		if resourceMap != nil {
			asyncRespPayload["response"] = resourceMap
			provPayload["data"] = resourceMap
		}
		provURN = ProvPutFullURN
	case "PATCH":
		asyncRespPayload["status"] = "200"
		if resourceMap != nil {
			asyncRespPayload["response"] = resourceMap
		}
		attrs := patchPaths
		if len(attrs) == 0 {
			attrs = []string{"displayName"}
		}
		provPayload["attributes"] = attrs
		provURN = ProvPatchNoticeURN
	case "DELETE":
		asyncRespPayload["status"] = "204"
		provURN = ProvDeleteURN
	default:
		asyncRespPayload["status"] = "201"
		if resourceMap != nil {
			asyncRespPayload["response"] = resourceMap
			provPayload["data"] = resourceMap
		}
		provURN = ProvCreateFullURN
	}

	if resourceMap != nil {
		if meta, ok := resourceMap["meta"].(map[string]any); ok {
			if ver, ok := meta["version"].(string); ok && ver != "" {
				asyncRespPayload["version"] = ver
			}
		}
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
			AsyncRespEventURN: asyncRespPayload,
			provURN:           provPayload,
		},
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// buildErrorSETJson constructs an RFC 9967 'urn:ietf:params:scim:event:misc:asyncresp' SET
// reporting a failed asynchronous SCIM request.
func buildErrorSETJson(
	baseURL string,
	txnID uuid.UUID,
	resourceType string,
	resourceID *uuid.UUID,
	method string,
	opErr error,
) (string, error) {
	var scimErr *scim.ScimError
	if !errors.As(opErr, &scimErr) || scimErr == nil {
		scimErr = scim.NewScimError(http.StatusInternalServerError, "", "Internal server error")
	}

	statusStr := fmt.Sprintf("%d", scimErr.Status)
	errResp := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  statusStr,
		"detail":  scimErr.Detail,
	}
	if scimErr.ScimType != "" {
		errResp["scimType"] = scimErr.ScimType
	}

	upperMethod := strings.ToUpper(method)
	asyncRespPayload := map[string]any{
		"status":   statusStr,
		"method":   upperMethod,
		"response": errResp,
	}

	payload := map[string]any{
		"iss": baseURL,
		"iat": time.Now().UTC().Unix(),
		"jti": uuid.New().String(),
		"txn": txnID.String(),
		"events": map[string]any{
			AsyncRespEventURN: asyncRespPayload,
		},
	}

	if resourceID != nil && *resourceID != uuid.Nil {
		plural := "Users"
		if strings.EqualFold(resourceType, "group") {
			plural = "Groups"
		}
		resourceURI := baseURL + "/" + plural + "/" + resourceID.String()
		asyncRespPayload["location"] = resourceURI
		payload["sub_id"] = map[string]any{
			"format": "uri",
			"uri":    resourceURI,
		}
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		fallback := fmt.Sprintf(`{"iss":%q,"iat":%d,"jti":%q,"txn":%q,"events":{%q:{"status":"500","method":%q,"response":{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":"Internal server error"}}}}`,
			baseURL, time.Now().UTC().Unix(), uuid.New().String(), txnID.String(), AsyncRespEventURN, upperMethod)
		return fallback, nil
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
		if event.SetPayload == nil || strings.TrimSpace(*event.SetPayload) == "" {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Asynchronous event payload missing"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(*event.SetPayload))
		return

	case model.AsyncStatusFailed:
		if event.SetPayload != nil && strings.TrimSpace(*event.SetPayload) != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(*event.SetPayload))
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Asynchronous operation failed"))
		return

	default:
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Unknown event status"))
		return
	}
}
