package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
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

func (h *UserHandler) executeCreateUser(ctx context.Context, wsID uuid.UUID, baseURL string, body map[string]any) (*model.ScimUser, error) {
	if h.userRepo == nil {
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	userName, _ := body["userName"].(string)
	userName = scim.NormalizeNFC(userName)
	if userName == "" {
		return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "userName is required")
	}

	exists, err := h.userRepo.ExistsByUserNameAndWorkspaceID(ctx, userName, wsID)
	if err != nil {
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}
	if exists {
		return nil, scim.NewScimError(http.StatusConflict, "uniqueness", "User with userName '"+userName+"' already exists")
	}

	user := &model.ScimUser{
		ID:           uuid.New(),
		WorkspaceID:  wsID,
		Active:       true,
		CreatedAt:    time.Now().UTC(),
		LastModified: time.Now().UTC(),
		Version:      0,
	}
	if err := scim.ApplyFromScimInput(user, body); err != nil {
		return nil, err
	}
	h.resolveManagerMetadata(ctx, user, wsID, baseURL)

	if err := h.userRepo.Create(ctx, user); err != nil {
		if isUserNameConflict(err) {
			return nil, scim.NewScimError(http.StatusConflict, "uniqueness",
				"User with userName '"+user.UserName+"' already exists")
		}
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create user")
	}

	h.touchWorkspace(ctx, wsID)
	return user, nil
}

func (h *UserHandler) executeReplaceUser(ctx context.Context, wsID, userID uuid.UUID, baseURL string, body map[string]any, ifMatch string) (*model.ScimUser, error) {
	if h.userRepo == nil {
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	user, err := h.userRepo.FindByIDAndWorkspaceID(ctx, userID, wsID)
	if err != nil || user == nil {
		return nil, scim.NewScimError(http.StatusNotFound, "", "User not found")
	}

	if !checkETagMatch(ifMatch, user.Version) {
		return nil, scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch")
	}

	newUserName, _ := body["userName"].(string)
	newUserName = scim.NormalizeNFC(newUserName)
	if newUserName != "" && !strings.EqualFold(newUserName, user.UserName) {
		exists, err := h.userRepo.ExistsByUserNameAndWorkspaceID(ctx, newUserName, wsID)
		if err != nil {
			return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
		}
		if exists {
			return nil, scim.NewScimError(http.StatusConflict, "uniqueness", "User with userName '"+newUserName+"' already exists")
		}
	}

	scim.ClearMutableAttributes(user)
	if err := scim.ApplyFromScimInput(user, body); err != nil {
		return nil, err
	}
	h.resolveManagerMetadata(ctx, user, wsID, baseURL)
	user.LastModified = time.Now().UTC()

	if err := h.userRepo.Update(ctx, user); err != nil {
		if errors.Is(err, repository.ErrOptimisticLock) {
			return nil, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed")
		}
		if isUserNameConflict(err) {
			return nil, scim.NewScimError(http.StatusConflict, "uniqueness",
				"User with userName '"+user.UserName+"' already exists")
		}
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update user")
	}

	h.touchWorkspace(ctx, wsID)
	return user, nil
}

func (h *UserHandler) executePatchUser(ctx context.Context, wsID, userID uuid.UUID, baseURL string, ops []map[string]any, ifMatch string) (*model.ScimUser, error) {
	if h.userRepo == nil {
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	user, err := h.userRepo.FindByIDAndWorkspaceID(ctx, userID, wsID)
	if err != nil || user == nil {
		return nil, scim.NewScimError(http.StatusNotFound, "", "User not found")
	}

	if !checkETagMatch(ifMatch, user.Version) {
		return nil, scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch")
	}

	before := scim.CloneScimUser(user)
	if err := scim.ApplyPatchOperations(user, ops); err != nil {
		return nil, err
	}
	h.resolveManagerMetadata(ctx, user, wsID, baseURL)

	if !scim.ScimUserMutableEqual(before, user) {
		if !strings.EqualFold(user.UserName, before.UserName) {
			exists, err := h.userRepo.ExistsByUserNameAndWorkspaceID(ctx, user.UserName, wsID)
			if err != nil {
				return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
			}
			if exists {
				return nil, scim.NewScimError(http.StatusConflict, "uniqueness", "User with userName '"+user.UserName+"' already exists")
			}
		}

		user.LastModified = time.Now().UTC()
		if err := h.userRepo.Update(ctx, user); err != nil {
			if errors.Is(err, repository.ErrOptimisticLock) {
				return nil, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed")
			}
			if isUserNameConflict(err) {
				return nil, scim.NewScimError(http.StatusConflict, "uniqueness",
					"User with userName '"+user.UserName+"' already exists")
			}
			return nil, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update user")
		}

		h.touchWorkspace(ctx, wsID)
	}

	return user, nil
}

func (h *UserHandler) executeDeleteUser(ctx context.Context, wsID, userID uuid.UUID, ifMatch string) error {
	if h.userRepo == nil {
		return scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	user, err := h.userRepo.FindByIDAndWorkspaceID(ctx, userID, wsID)
	if err != nil || user == nil {
		return scim.NewScimError(http.StatusNotFound, "", "User not found")
	}

	if !checkETagMatch(ifMatch, user.Version) {
		return scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch")
	}

	if h.membershipRepo != nil {
		if err := h.membershipRepo.DeleteByMemberValue(ctx, userID); err != nil {
			slog.Error("failed to delete memberships", "error", err)
		}
	}

	if err := h.userRepo.Delete(ctx, userID, wsID); err != nil {
		return scim.NewScimError(http.StatusInternalServerError, "", "Failed to delete user")
	}

	h.touchWorkspace(ctx, wsID)
	return nil
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	var input map[string]any
	if err := readJSON(w, r, &input); err != nil {
		writeReadJSONError(w, err)
		return
	}

	userName, _ := input["userName"].(string)
	userName = scim.NormalizeNFC(userName)
	if userName == "" {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "userName is required"))
		return
	}
	if err := scim.ValidatePasswordInput(input); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	baseURL := buildBaseURL(r)

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		compat := getCompatMode(r)
		dispatchAsyncOperation(w, r, h.asyncEventRepo, wsID, baseURL, prefHeader, "POST", "User", nil, func(workerCtx context.Context, txnID uuid.UUID) (*uuid.UUID, string, error) {
			user, err := h.executeCreateUser(workerCtx, wsID, baseURL, input)
			if err != nil {
				return nil, "", err
			}
			resp := scim.UserToScimResponse(user, baseURL, nil)
			if compat == scim.CompatMS {
				resp = scim.ApplyMsCompat(resp)
			}
			setStr, err := buildSETJson(baseURL, txnID, "User", user.ID, "POST", resp)
			if err != nil {
				return &user.ID, "", err
			}
			return &user.ID, setStr, nil
		})
		return
	}

	user, err := h.executeCreateUser(r.Context(), wsID, baseURL, input)
	if err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

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
	if ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match")); ifNoneMatch != "" && checkETagMatch(ifNoneMatch, user.Version) {
		w.WriteHeader(http.StatusNotModified)
		return
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
	if err := readJSON(w, r, &input); err != nil {
		writeReadJSONError(w, err)
		return
	}
	if err := scim.ValidatePasswordInput(input); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	baseURL := buildBaseURL(r)
	ifMatch := r.Header.Get("If-Match")

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		compat := getCompatMode(r)
		dispatchAsyncOperation(w, r, h.asyncEventRepo, wsID, baseURL, prefHeader, "PUT", "User", &userID, func(workerCtx context.Context, txnID uuid.UUID) (*uuid.UUID, string, error) {
			u, err := h.executeReplaceUser(workerCtx, wsID, userID, baseURL, input, ifMatch)
			if err != nil {
				return &userID, "", err
			}
			groups := h.getUserGroups(workerCtx, u.ID, baseURL)
			resp := scim.UserToScimResponse(u, baseURL, groups)
			if compat == scim.CompatMS {
				resp = scim.ApplyMsCompat(resp)
			}
			setStr, err := buildSETJson(baseURL, txnID, "User", u.ID, "PUT", resp)
			if err != nil {
				return &userID, "", err
			}
			return &userID, setStr, nil
		})
		return
	}

	user, err := h.executeReplaceUser(r.Context(), wsID, userID, baseURL, input, ifMatch)
	if err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

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
	if err := readJSON(w, r, &patchReq); err != nil {
		writeReadJSONError(w, err)
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

	baseURL := buildBaseURL(r)
	ifMatch := r.Header.Get("If-Match")

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		compat := getCompatMode(r)
		dispatchAsyncOperation(w, r, h.asyncEventRepo, wsID, baseURL, prefHeader, "PATCH", "User", &userID, func(workerCtx context.Context, txnID uuid.UUID) (*uuid.UUID, string, error) {
			u, err := h.executePatchUser(workerCtx, wsID, userID, baseURL, operations, ifMatch)
			if err != nil {
				return &userID, "", err
			}
			groups := h.getUserGroups(workerCtx, u.ID, baseURL)
			resp := scim.UserToScimResponse(u, baseURL, groups)
			if compat == scim.CompatMS {
				resp = scim.ApplyMsCompat(resp)
			}
			patchPaths := extractModifiedPatchPaths(operations)
			setStr, err := buildSETJson(baseURL, txnID, "User", u.ID, "PATCH", resp, patchPaths...)
			if err != nil {
				return &userID, "", err
			}
			return &userID, setStr, nil
		})
		return
	}

	user, err := h.executePatchUser(r.Context(), wsID, userID, baseURL, operations, ifMatch)
	if err != nil {
		var scimErr *scim.ScimError
		if errors.As(err, &scimErr) {
			scim.WriteScimError(w, scimErr)
			return
		}
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", err.Error()))
		return
	}

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

	ifMatch := r.Header.Get("If-Match")

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		baseURL := buildBaseURL(r)
		dispatchAsyncOperation(w, r, h.asyncEventRepo, wsID, baseURL, prefHeader, "DELETE", "User", &userID, func(workerCtx context.Context, txnID uuid.UUID) (*uuid.UUID, string, error) {
			if err := h.executeDeleteUser(workerCtx, wsID, userID, ifMatch); err != nil {
				return &userID, "", err
			}
			setStr, err := buildSETJson(baseURL, txnID, "User", userID, "DELETE", nil)
			if err != nil {
				return &userID, "", err
			}
			return &userID, setStr, nil
		})
		return
	}

	if err := h.executeDeleteUser(r.Context(), wsID, userID, ifMatch); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	// POST /.search: parse JSON body and inject into query params for ListUsers
	var body map[string]any
	if err := readJSON(w, r, &body); err != nil && !errors.Is(err, io.EOF) {
		writeReadJSONError(w, err)
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
		if si, exists := body["startIndex"]; exists && si != nil {
			num, ok := si.(float64)
			if !ok || math.IsNaN(num) || math.IsInf(num, 0) || num != math.Trunc(num) {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "startIndex must be an integer"))
				return
			}
			q.Set("startIndex", strconv.Itoa(int(num)))
		}
		if f, ok := body["filter"].(string); ok {
			q.Set("filter", f)
		}
		if cnt, exists := body["count"]; exists && cnt != nil {
			num, ok := cnt.(float64)
			if !ok || math.IsNaN(num) || math.IsInf(num, 0) || num != math.Trunc(num) {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "count must be an integer"))
				return
			}
			q.Set("count", strconv.Itoa(int(num)))
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

func (h *UserHandler) resolveManagerMetadata(ctx context.Context, user *model.ScimUser, wsID uuid.UUID, baseURL string) {
	if user == nil {
		return
	}
	if user.EnterpriseManagerValue == nil || strings.TrimSpace(*user.EnterpriseManagerValue) == "" {
		user.EnterpriseManagerDisplay = nil
		user.EnterpriseManagerRef = nil
		return
	}
	user.EnterpriseManagerDisplay = nil
	if h.userRepo == nil {
		return
	}
	mgrID, err := uuid.Parse(strings.TrimSpace(*user.EnterpriseManagerValue))
	if err != nil {
		return
	}
	mgr, err := h.userRepo.FindByIDAndWorkspaceID(ctx, mgrID, wsID)
	if err != nil || mgr == nil {
		return
	}
	if mgr.DisplayName != nil && *mgr.DisplayName != "" {
		dn := *mgr.DisplayName
		user.EnterpriseManagerDisplay = &dn
	} else if mgr.UserName != "" {
		un := mgr.UserName
		user.EnterpriseManagerDisplay = &un
	}
	ref := baseURL + "/Users/" + mgr.ID.String()
	user.EnterpriseManagerRef = &ref
}

func (h *UserHandler) getUserGroups(ctx context.Context, userID uuid.UUID, baseURL string) []map[string]any {
	if h.membershipRepo == nil {
		return nil
	}
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
	if len(users) == 0 || h.membershipRepo == nil {
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
	if h.workspaceRepo == nil {
		return
	}
	if err := h.workspaceRepo.TouchUpdatedAt(ctx, wsID); err != nil {
		slog.Error("failed to touch workspace", "error", err)
	}
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
