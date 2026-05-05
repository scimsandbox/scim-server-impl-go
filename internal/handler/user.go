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
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

type UserHandler struct {
	userRepo       *repository.UserRepository
	membershipRepo *repository.MembershipRepository
	workspaceRepo  *repository.WorkspaceRepository
}

func NewUserHandler(
	userRepo *repository.UserRepository,
	membershipRepo *repository.MembershipRepository,
	workspaceRepo *repository.WorkspaceRepository,
) *UserHandler {
	return &UserHandler{
		userRepo:       userRepo,
		membershipRepo: membershipRepo,
		workspaceRepo:  workspaceRepo,
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
	scim.ApplyFromScimInput(user, input)

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create user"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	response := scim.UserToScimResponse(user, baseURL, nil)

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

	startIndex := clampInt(r.URL.Query().Get("startIndex"), 1, 1)
	count := clampIntMax(r.URL.Query().Get("count"), 10, 0, 200)
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

	offset := max(0, startIndex-1)
	pageNumber := 0
	skipWithinPage := 0
	if count > 0 {
		pageNumber = offset / count
		skipWithinPage = offset % count
	}

	users, err := h.userRepo.List(r.Context(), wsID, whereClause, filterArgs, sortColumn, sortDir, pageNumber*count, count)
	if err != nil {
		slog.Error("list users failed", "error", err)
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
		return
	}

	// Skip within page
	if skipWithinPage > 0 && skipWithinPage < len(users) {
		users = users[skipWithinPage:]
	} else if skipWithinPage >= len(users) {
		users = nil
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

	listResponse := map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": totalCount,
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}

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

	user, err := h.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	// If-Match check
	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" {
		etag := fmt.Sprintf("W/\"%d\"", user.Version)
		if ifMatch != etag {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch"))
			return
		}
	}

	var input map[string]any
	if err := readJSON(r, &input); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
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
	scim.ApplyFromScimInput(user, input)
	user.LastModified = time.Now()

	if err := h.userRepo.Update(r.Context(), user); err != nil {
		if errors.Is(err, repository.ErrOptimisticLock) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed"))
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update user"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	groups := h.getUserGroups(r.Context(), user.ID, baseURL)
	response := scim.UserToScimResponse(user, baseURL, groups)

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

	user, err := h.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "User not found"))
		return
	}

	// If-Match check
	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" {
		etag := fmt.Sprintf("W/\"%d\"", user.Version)
		if ifMatch != etag {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch"))
			return
		}
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

	if err := scim.ApplyPatchOperations(user, operations); err != nil {
		var scimErr *scim.ScimError
		if errors.As(err, &scimErr) {
			scim.WriteScimError(w, scimErr)
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", err.Error()))
		return
	}

	user.LastModified = time.Now()

	if err := h.userRepo.Update(r.Context(), user); err != nil {
		if errors.Is(err, repository.ErrOptimisticLock) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed"))
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update user"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	groups := h.getUserGroups(r.Context(), user.ID, baseURL)
	response := scim.UserToScimResponse(user, baseURL, groups)

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
	if f, ok := body["filter"].(string); ok {
		q.Set("filter", f)
	}
	if si, ok := body["startIndex"].(float64); ok {
		q.Set("startIndex", strconv.Itoa(int(si)))
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
