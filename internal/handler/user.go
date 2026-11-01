package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

type UserHandler struct {
	userRepo       *repository.UserRepository
	membershipRepo *repository.MembershipRepository
	workspaceRepo  *repository.WorkspaceRepository
	asyncEventRepo repository.AsyncEventRepo
}

func NewUserHandler(
	userRepo *repository.UserRepository,
	membershipRepo *repository.MembershipRepository,
	workspaceRepo *repository.WorkspaceRepository,
	asyncEventRepo ...repository.AsyncEventRepo,
) *UserHandler {
	var ar repository.AsyncEventRepo
	if len(asyncEventRepo) > 0 {
		ar = asyncEventRepo[0]
	}
	return &UserHandler{
		userRepo:       userRepo,
		membershipRepo: membershipRepo,
		workspaceRepo:  workspaceRepo,
		asyncEventRepo: ar,
	}
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	var input map[string]any
	if err := readJSON(r, &input); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
		return
	}

	userName, _ := input["userName"].(string)
	if userName == "" {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "userName is required"))
		return
	}

	if isAsyncPreferred(r) && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "POST",
			ResourceType: "User",
			Status:       model.AsyncStatusPending,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", "respond-async")
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		go func(detachedInput map[string]any, ws uuid.UUID, txn uuid.UUID, base string, compat scim.CompatMode) {
			workerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			user := &model.ScimUser{
				ID:           uuid.New(),
				WorkspaceID:  ws,
				Active:       true,
				CreatedAt:    time.Now().UTC(),
				LastModified: time.Now().UTC(),
				Version:      0,
			}
			if err := scim.ApplyFromScimInput(user, detachedInput); err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, nil, nil, time.Now().UTC())
				return
			}
			if err := h.userRepo.Create(workerCtx, user); err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, nil, nil, time.Now().UTC())
				return
			}
			h.touchWorkspace(workerCtx, ws)

			resp := scim.UserToScimResponse(user, base, nil)
			if compat == scim.CompatMS {
				resp = scim.ApplyMsCompat(resp)
			}
			setStr, err := buildSETJson(base, txn, "User", user.ID, "POST", resp)
			if err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &user.ID, nil, time.Now().UTC())
				return
			}
			_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusCompleted, &user.ID, &setStr, time.Now().UTC())
		}(input, wsID, txnID, baseURL, getCompatMode(r))
		return
	}

	exists, err := h.userRepo.ExistsByUserNameAndWorkspaceID(r.Context(), userName, wsID)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
		return
	}
	if exists {
		scim.WriteScimError(w, scim.NewScimError(http.StatusConflict, "uniqueness", "User with userName '"+userName+"' already exists"))
		return
	}

	user := &model.ScimUser{
		ID:           uuid.New(),
		WorkspaceID:  wsID,
		Active:       true,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
		Version:      0,
	}
	if err := scim.ApplyFromScimInput(user, input); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		if isUserNameConflict(err) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusConflict, "uniqueness",
				"User with userName '"+user.UserName+"' already exists"))
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create user"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	response := scim.UserToScimResponse(user, baseURL, nil)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	if getCompatMode(r) == scim.CompatMS {
		response = scim.ApplyMsCompat(response)
	}

	resourceURL := baseURL + "/Users/" + user.ID.String()
	w.Header().Set("Location", resourceURL)
	w.Header().Set("Content-Location", resourceURL)
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", user.Version))
	writeJSON(w, http.StatusCreated, response)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	userID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	user, err := h.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	// If-None-Match → 304
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" {
		etag := fmt.Sprintf("W/\"%d\"", user.Version)
		if ifNoneMatch == etag || ifNoneMatch == "*" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	baseURL := buildBaseURL(r)
	groups := h.getUserGroups(r.Context(), user.ID, baseURL)
	response := scim.UserToScimResponse(user, baseURL, groups)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	if getCompatMode(r) == scim.CompatMS {
		response = scim.ApplyMsCompat(response)
	}

	w.Header().Set("Content-Location", baseURL+"/Users/"+user.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", user.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	pag, scimErr := parsePagination(r.URL.Query(), nil, wsID, 10)
	if scimErr != nil {
		scim.WriteScimError(w, scimErr)
		return
	}
	filterStr := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sortBy")
	sortOrder := r.URL.Query().Get("sortOrder")
	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")

	var filterResult *scim.FilterResult
	if filterStr != "" {
		fr, err := scim.ParseUserFilter(filterStr, 2)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidFilter", err.Error()))
			return
		}
		filterResult = fr
	}

	sortColumn := ""
	if sortBy != "" {
		col := scim.ResolveUserSortAttribute(sortBy)
		if col == "" {
			scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Unsupported sortBy attribute: "+sortBy))
			return
		}
		sortColumn = col
	}

	sortDir := "ASC"
	if strings.EqualFold(sortOrder, "descending") {
		sortDir = "DESC"
	}

	var whereClause string
	var filterArgs []any
	if filterResult != nil {
		whereClause = filterResult.SQL
		filterArgs = filterResult.Args
	}

	totalCount, err := h.userRepo.Count(r.Context(), wsID, whereClause, filterArgs)
	if err != nil {
		slog.Error("count users failed", "error", err)
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
		return
	}

	var users []*model.ScimUser
	if pag.Count > 0 {
		var err error
		users, err = h.userRepo.List(r.Context(), wsID, whereClause, filterArgs, sortColumn, sortDir, pag.Offset, pag.Count)
		if err != nil {
			slog.Error("list users failed", "error", err)
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
	}

	baseURL := buildBaseURL(r)
	compat := getCompatMode(r)

	// Batch load groups for all users
	groupsMap := h.getUserGroupsBatch(r.Context(), users, baseURL)

	resources := make([]map[string]any, 0, len(users))
	for _, user := range users {
		groups := groupsMap[user.ID]
		response := scim.UserToScimResponse(user, baseURL, groups)
		response = applyAttributeProjection(response, attrs, excludedAttrs)
		if compat == scim.CompatMS {
			response = scim.ApplyMsCompat(response)
		}
		resources = append(resources, response)
	}

	listResponse := buildListResponse(pag, wsID, int(totalCount), resources)
	writeJSON(w, http.StatusOK, listResponse)
}

func (h *UserHandler) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	userID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	var input map[string]any
	if err := readJSON(r, &input); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
		return
	}

	if isAsyncPreferred(r) && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "PUT",
			ResourceType: "User",
			ResourceID:   &userID,
			Status:       model.AsyncStatusPending,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", "respond-async")
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		go func(detachedInput map[string]any, ws uuid.UUID, uid uuid.UUID, txn uuid.UUID, base string, compat scim.CompatMode) {
			workerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			u, err := h.userRepo.FindByIDAndWorkspaceID(workerCtx, uid, ws)
			if err != nil || u == nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			scim.ClearMutableAttributes(u)
			if err := scim.ApplyFromScimInput(u, detachedInput); err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			u.LastModified = time.Now().UTC()
			if err := h.userRepo.Update(workerCtx, u); err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			h.touchWorkspace(workerCtx, ws)

			groups := h.getUserGroups(workerCtx, u.ID, base)
			resp := scim.UserToScimResponse(u, base, groups)
			if compat == scim.CompatMS {
				resp = scim.ApplyMsCompat(resp)
			}
			setStr, err := buildSETJson(base, txn, "User", u.ID, "PUT", resp)
			if err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusCompleted, &uid, &setStr, time.Now().UTC())
		}(input, wsID, userID, txnID, baseURL, getCompatMode(r))
		return
	}

	user, err := h.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	// If-Match check (RFC 7232 §3.1 / RFC 7644 §3.14 wildcard support)
	ifMatch := r.Header.Get("If-Match")
	if !checkETagMatch(ifMatch, user.Version) {
		scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch"))
		return
	}

	newUserName, _ := input["userName"].(string)
	if newUserName != "" && !strings.EqualFold(newUserName, user.UserName) {
		exists, err := h.userRepo.ExistsByUserNameAndWorkspaceID(r.Context(), newUserName, wsID)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
		if exists {
			scim.WriteScimError(w, scim.NewScimError(http.StatusConflict, "uniqueness", "User with userName '"+newUserName+"' already exists"))
			return
		}
	}

	scim.ClearMutableAttributes(user)
	if err := scim.ApplyFromScimInput(user, input); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}
	user.LastModified = time.Now()

	if err := h.userRepo.Update(r.Context(), user); err != nil {
		if errors.Is(err, repository.ErrOptimisticLock) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed"))
			return
		}
		if isUserNameConflict(err) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusConflict, "uniqueness",
				"User with userName '"+user.UserName+"' already exists"))
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update user"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	groups := h.getUserGroups(r.Context(), user.ID, baseURL)
	response := scim.UserToScimResponse(user, baseURL, groups)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	if getCompatMode(r) == scim.CompatMS {
		response = scim.ApplyMsCompat(response)
	}

	w.Header().Set("Content-Location", baseURL+"/Users/"+user.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", user.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *UserHandler) PatchUser(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	userID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	var patchReq map[string]any
	if err := readJSON(r, &patchReq); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
		return
	}

	// Validate PatchOp schema
	schemas, _ := patchReq["schemas"].([]any)
	validSchema := false
	for _, s := range schemas {
		if s == "urn:ietf:params:scim:api:messages:2.0:PatchOp" {
			validSchema = true
			break
		}
	}
	if !validSchema {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue",
			"Missing or invalid schema: urn:ietf:params:scim:api:messages:2.0:PatchOp"))
		return
	}

	ops, _ := patchReq["Operations"].([]any)
	if len(ops) == 0 {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "No operations provided"))
		return
	}

	operations := make([]map[string]any, 0, len(ops))
	for _, op := range ops {
		if m, ok := op.(map[string]any); ok {
			operations = append(operations, m)
		}
	}

	if isAsyncPreferred(r) && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "PATCH",
			ResourceType: "User",
			ResourceID:   &userID,
			Status:       model.AsyncStatusPending,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", "respond-async")
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		go func(detachedOps []map[string]any, ws uuid.UUID, uid uuid.UUID, txn uuid.UUID, base string, compat scim.CompatMode) {
			workerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			u, err := h.userRepo.FindByIDAndWorkspaceID(workerCtx, uid, ws)
			if err != nil || u == nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			if err := scim.ApplyPatchOperations(u, detachedOps); err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			u.LastModified = time.Now().UTC()
			if err := h.userRepo.Update(workerCtx, u); err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			h.touchWorkspace(workerCtx, ws)

			groups := h.getUserGroups(workerCtx, u.ID, base)
			resp := scim.UserToScimResponse(u, base, groups)
			if compat == scim.CompatMS {
				resp = scim.ApplyMsCompat(resp)
			}
			setStr, err := buildSETJson(base, txn, "User", u.ID, "PATCH", resp)
			if err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusCompleted, &uid, &setStr, time.Now().UTC())
		}(operations, wsID, userID, txnID, baseURL, getCompatMode(r))
		return
	}

	user, err := h.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	oldUserName := user.UserName

	// If-Match check (RFC 7232 §3.1 / RFC 7644 §3.14 wildcard support)
	ifMatch := r.Header.Get("If-Match")
	if !checkETagMatch(ifMatch, user.Version) {
		scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch"))
		return
	}

	if err := scim.ApplyPatchOperations(user, operations); err != nil {
		var scimErr *scim.ScimError
		if errors.As(err, &scimErr) {
			scim.WriteScimError(w, scimErr)
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", err.Error()))
		return
	}

	if !strings.EqualFold(user.UserName, oldUserName) {
		exists, err := h.userRepo.ExistsByUserNameAndWorkspaceID(r.Context(), user.UserName, wsID)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
		if exists {
			scim.WriteScimError(w, scim.NewScimError(http.StatusConflict, "uniqueness", "User with userName '"+user.UserName+"' already exists"))
			return
		}
	}

	user.LastModified = time.Now()

	if err := h.userRepo.Update(r.Context(), user); err != nil {
		if errors.Is(err, repository.ErrOptimisticLock) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed"))
			return
		}
		if isUserNameConflict(err) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusConflict, "uniqueness",
				"User with userName '"+user.UserName+"' already exists"))
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update user"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	groups := h.getUserGroups(r.Context(), user.ID, baseURL)
	response := scim.UserToScimResponse(user, baseURL, groups)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	if getCompatMode(r) == scim.CompatMS {
		response = scim.ApplyMsCompat(response)
	}

	w.Header().Set("Content-Location", baseURL+"/Users/"+user.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", user.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	userID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	if isAsyncPreferred(r) && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "DELETE",
			ResourceType: "User",
			ResourceID:   &userID,
			Status:       model.AsyncStatusPending,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", "respond-async")
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		go func(ws uuid.UUID, uid uuid.UUID, txn uuid.UUID, base string) {
			workerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			_ = h.membershipRepo.DeleteByMemberValue(workerCtx, uid)
			if err := h.userRepo.Delete(workerCtx, uid, ws); err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			h.touchWorkspace(workerCtx, ws)

			setStr, err := buildSETJson(base, txn, "User", uid, "DELETE", nil)
			if err != nil {
				_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusFailed, &uid, nil, time.Now().UTC())
				return
			}
			_ = h.asyncEventRepo.UpdateStatusAndPayload(workerCtx, txn, model.AsyncStatusCompleted, &uid, &setStr, time.Now().UTC())
		}(wsID, userID, txnID, baseURL)
		return
	}

	user, err := h.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	// Delete memberships first
	if err := h.membershipRepo.DeleteByMemberValue(r.Context(), userID); err != nil {
		slog.Error("failed to delete memberships", "error", err)
	}

	if err := h.userRepo.Delete(r.Context(), userID, wsID); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to delete user"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	// POST /.search: parse JSON body and inject into query params for ListUsers
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
		return
	}

	q := r.URL.Query()
	if body != nil {
		if cur, exists := body["cursor"]; exists {
			if curStr, ok := cur.(string); ok {
				q.Set("cursor", curStr)
			} else {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidCursor", "cursor must be a string"))
				return
			}
		}
		if si, exists := body["startIndex"]; exists {
			if num, ok := si.(float64); ok {
				q.Set("startIndex", strconv.Itoa(int(num)))
			} else {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "startIndex must be an integer"))
				return
			}
		}
		if f, ok := body["filter"].(string); ok {
			q.Set("filter", f)
		}
		if c, ok := body["count"].(float64); ok {
			q.Set("count", strconv.Itoa(int(c)))
		}
		if sb, ok := body["sortBy"].(string); ok {
			q.Set("sortBy", sb)
		}
		if so, ok := body["sortOrder"].(string); ok {
			q.Set("sortOrder", so)
		}
		if a, ok := body["attributes"].([]any); ok {
			strs := make([]string, 0, len(a))
			for _, v := range a {
				if s, ok := v.(string); ok {
					strs = append(strs, s)
				}
			}
			q.Set("attributes", strings.Join(strs, ","))
		}
		if ea, ok := body["excludedAttributes"].([]any); ok {
			strs := make([]string, 0, len(ea))
			for _, v := range ea {
				if s, ok := v.(string); ok {
					strs = append(strs, s)
				}
			}
			q.Set("excludedAttributes", strings.Join(strs, ","))
		}
	}
	r.URL.RawQuery = q.Encode()

	h.ListUsers(w, r)
}

func (h *UserHandler) getUserGroups(ctx context.Context, userID uuid.UUID, baseURL string) []map[string]any {
	memberships, err := h.membershipRepo.FindByMemberValueWithGroup(ctx, userID)
	if err != nil {
		return nil
	}
	groups := make([]map[string]any, 0, len(memberships))
	for _, m := range memberships {
		groups = append(groups, scim.BuildUserGroupRef(m.Membership.GroupID, m.GroupDisplayName, baseURL))
	}
	return groups
}

func (h *UserHandler) getUserGroupsBatch(ctx context.Context, users []*model.ScimUser, baseURL string) map[uuid.UUID][]map[string]any {
	result := make(map[uuid.UUID][]map[string]any)
	if len(users) == 0 {
		return result
	}

	userIDs := make([]uuid.UUID, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	memberships, err := h.membershipRepo.FindByMemberValueInWithGroup(ctx, userIDs)
	if err != nil {
		return result
	}

	for _, m := range memberships {
		ref := scim.BuildUserGroupRef(m.Membership.GroupID, m.GroupDisplayName, baseURL)
		result[m.Membership.MemberValue] = append(result[m.Membership.MemberValue], ref)
	}

	return result
}

func (h *UserHandler) touchWorkspace(ctx context.Context, wsID uuid.UUID) {
	if err := h.workspaceRepo.TouchUpdatedAt(ctx, wsID); err != nil {
		slog.Error("failed to touch workspace", "error", err)
	}
}

func clampInt(s string, defaultVal, minVal int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	if v < minVal {
		return minVal
	}
	return v
}

func clampIntMax(s string, defaultVal, minVal, maxVal int) int {
	v := clampInt(s, defaultVal, minVal)
	if v > maxVal {
		return maxVal
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// userNameConstraints are the unique constraints on scim_users that a client can violate
// by choosing a userName: the original case-sensitive one and the case-insensitive index
// that enforces RFC 7643 §7's caseExact:false. A violation of any other constraint (an id
// collision) is an internal fault, not a client conflict, and must stay a 500.
var userNameConstraints = map[string]bool{
	"uk_scim_users_workspace_user_name":    true,
	"uk_scim_users_workspace_user_name_ci": true,
}

// isUserNameConflict reports whether err is the database rejecting a duplicate userName.
// The application pre-checks uniqueness before writing, so this only fires when a
// concurrent request claimed the name in between — the race the pre-check cannot close.
func isUserNameConflict(err error) bool {
	var uniqueErr jdbc.UniqueViolationError
	if !errors.As(err, &uniqueErr) {
		return false
	}
	return userNameConstraints[uniqueErr.Constraint]
}
