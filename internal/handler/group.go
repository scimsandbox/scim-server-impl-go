package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

var memberValueFilterRe = regexp.MustCompile(`(?i)value\s+eq\s+"([^"]+)"`)

type GroupHandler struct {
	groupRepo      *repository.GroupRepository
	membershipRepo *repository.MembershipRepository
	userRepo       *repository.UserRepository
	workspaceRepo  *repository.WorkspaceRepository
}

func NewGroupHandler(
	groupRepo *repository.GroupRepository,
	membershipRepo *repository.MembershipRepository,
	userRepo *repository.UserRepository,
	workspaceRepo *repository.WorkspaceRepository,
) *GroupHandler {
	return &GroupHandler{
		groupRepo:      groupRepo,
		membershipRepo: membershipRepo,
		userRepo:       userRepo,
		workspaceRepo:  workspaceRepo,
	}
}

func (h *GroupHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
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

	displayName, _ := input["displayName"].(string)
	if displayName == "" {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "displayName is required"))
		return
	}

	existing, err := h.groupRepo.FindByDisplayNameAndWorkspaceID(r.Context(), displayName, wsID)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
		return
	}
	if existing != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusConflict, "uniqueness",
			"Group with displayName '"+displayName+"' already exists"))
		return
	}

	group := &model.ScimGroup{
		ID:           uuid.New(),
		WorkspaceID:  wsID,
		DisplayName:  displayName,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
		Version:      0,
	}

	if extID, ok := input["externalId"].(string); ok {
		group.ExternalID = &extID
	}

	if err := h.groupRepo.Create(r.Context(), group); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create group"))
		return
	}

	// Add members
	if members, ok := input["members"].([]any); ok {
		for _, m := range members {
			if memberMap, ok := m.(map[string]any); ok {
				if err := h.addMember(r.Context(), group.ID, wsID, memberMap); err != nil {
					var se *scim.ScimError
					if errors.As(err, &se) {
						scim.WriteScimError(w, se)
						return
					}
					scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", err.Error()))
					return
				}
			}
		}
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	memberships, _ := h.membershipRepo.FindByGroupID(r.Context(), group.ID)
	group.Members = memberships
	response := scim.GroupToScimResponse(group, baseURL)

	resourceURL := baseURL + "/Groups/" + group.ID.String()
	w.Header().Set("Location", resourceURL)
	w.Header().Set("Content-Location", resourceURL)
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", group.Version))
	writeJSON(w, http.StatusCreated, response)
}

func (h *GroupHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Group not found"))
		return
	}

	group, err := h.groupRepo.FindByIDAndWorkspaceID(r.Context(), groupID, wsID)
	if err != nil || group == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Group not found"))
		return
	}

	// Load members
	memberships, _ := h.membershipRepo.FindByGroupID(r.Context(), group.ID)
	group.Members = memberships

	// If-None-Match
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" {
		etag := fmt.Sprintf("W/\"%d\"", group.Version)
		if ifNoneMatch == etag || ifNoneMatch == "*" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	baseURL := buildBaseURL(r)
	response := scim.GroupToScimResponse(group, baseURL)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	w.Header().Set("Content-Location", baseURL+"/Groups/"+group.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", group.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *GroupHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	startIndex := clampInt(r.URL.Query().Get("startIndex"), 1, 1)
	count := clampIntMax(r.URL.Query().Get("count"), 100, 0, 200)
	filterStr := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sortBy")
	if sortBy == "" {
		sortBy = "displayName"
	}
	sortOrder := r.URL.Query().Get("sortOrder")
	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")

	var filterResult *scim.FilterResult
	if filterStr != "" {
		fr, err := scim.ParseGroupFilter(filterStr, 2)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidFilter", err.Error()))
			return
		}
		filterResult = fr
	}

	sortColumn := scim.ResolveGroupSortAttribute(sortBy)
	if sortColumn == "" {
		sortColumn = "display_name"
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

	totalCount, err := h.groupRepo.Count(r.Context(), wsID, whereClause, filterArgs)
	if err != nil {
		slog.Error("count groups failed", "error", err)
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
		return
	}

	if count == 0 {
		listResponse := map[string]any{
			"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			"totalResults": totalCount,
			"startIndex":   startIndex,
			"itemsPerPage": 0,
			"Resources":    []map[string]any{},
		}
		writeJSON(w, http.StatusOK, listResponse)
		return
	}

	offset := max(0, startIndex-1)
	pageNumber := offset / count
	skipWithinPage := offset % count

	groups, err := h.groupRepo.List(r.Context(), wsID, whereClause, filterArgs, sortColumn, sortDir, pageNumber*count, count)
	if err != nil {
		slog.Error("list groups failed", "error", err)
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
		return
	}

	if skipWithinPage > 0 && skipWithinPage < len(groups) {
		groups = groups[skipWithinPage:]
	} else if skipWithinPage >= len(groups) {
		groups = nil
	}

	baseURL := buildBaseURL(r)

	// Load members for all groups
	for _, g := range groups {
		memberships, _ := h.membershipRepo.FindByGroupID(r.Context(), g.ID)
		g.Members = memberships
	}

	resources := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		response := scim.GroupToScimResponse(g, baseURL)
		response = applyAttributeProjection(response, attrs, excludedAttrs)
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

func (h *GroupHandler) ReplaceGroup(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Group not found"))
		return
	}
	var input map[string]any
	if err := readJSON(r, &input); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
		return
	}

	displayName, _ := input["displayName"].(string)
	if displayName == "" {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "displayName is required"))
		return
	}

	var updatedGroup *model.ScimGroup
	err = jdbc.InTransaction(r.Context(), func(tx jdbc.Tx) error {
		group, err := h.groupRepo.FindByIDAndWorkspaceIDTx(r.Context(), tx, groupID, wsID)
		if err != nil || group == nil {
			return &scim.ScimError{Status: http.StatusNotFound, Detail: "Group not found"}
		}

		// If-Match
		ifMatch := r.Header.Get("If-Match")
		if ifMatch != "" {
			etag := fmt.Sprintf("W/\"%d\"", group.Version)
			if ifMatch != etag {
				return &scim.ScimError{Status: http.StatusPreconditionFailed, Detail: "ETag mismatch"}
			}
		}

		// Uniqueness check
		if displayName != group.DisplayName {
			existing, err := h.groupRepo.FindByDisplayNameAndWorkspaceIDTx(r.Context(), tx, displayName, wsID)
			if err != nil {
				return err
			}
			if existing != nil {
				return &scim.ScimError{Status: http.StatusConflict, ScimType: "uniqueness",
					Detail: "Group with displayName '" + displayName + "' already exists"}
			}
		}

		group.DisplayName = displayName
		if extID, ok := input["externalId"]; ok {
			if s, ok := extID.(string); ok {
				group.ExternalID = &s
			} else {
				group.ExternalID = nil
			}
		} else {
			group.ExternalID = nil
		}

		// Clear existing members
		if err := h.membershipRepo.DeleteByGroupIDTx(r.Context(), tx, group.ID); err != nil {
			slog.Error("failed to clear memberships", "error", err)
			return err
		}

		// Re-add members inside transaction
		if members, ok := input["members"].([]any); ok {
			for _, m := range members {
				if memberMap, ok := m.(map[string]any); ok {
					if err := h.addMemberTx(r.Context(), tx, group.ID, wsID, memberMap); err != nil {
						return err
					}
				}
			}
		}

		// Update group (also handles version bump / optimistic lock check)
		if err := h.groupRepo.UpdateTx(r.Context(), tx, group); err != nil {
			return err
		}

		// Reload memberships into group
		memberships, err := h.membershipRepo.FindByGroupIDTx(r.Context(), tx, group.ID)
		if err != nil {
			return err
		}
		group.Members = memberships

		updatedGroup = group
		return nil
	})

	if err != nil {
		var se *scim.ScimError
		if errors.As(err, &se) {
			scim.WriteScimError(w, se)
			return
		}
		if errors.Is(err, repository.ErrOptimisticLock) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed"))
			return
		}
		slog.Error("replace group failed", "error", err)
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update group"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	response := scim.GroupToScimResponse(updatedGroup, baseURL)

	w.Header().Set("Content-Location", baseURL+"/Groups/"+updatedGroup.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", updatedGroup.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *GroupHandler) PatchGroup(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Group not found"))
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
			"PATCH request must include PatchOp schema"))
		return
	}

	ops, _ := patchReq["Operations"].([]any)
	if len(ops) == 0 {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "PATCH Operations is required"))
		return
	}

	var updatedGroup *model.ScimGroup
	err = jdbc.InTransaction(r.Context(), func(tx jdbc.Tx) error {
		group, err := h.groupRepo.FindByIDAndWorkspaceIDTx(r.Context(), tx, groupID, wsID)
		if err != nil || group == nil {
			return &scim.ScimError{Status: http.StatusNotFound, Detail: "Group not found"}
		}

		// If-Match
		ifMatch := r.Header.Get("If-Match")
		if ifMatch != "" {
			etag := fmt.Sprintf("W/\"%d\"", group.Version)
			if ifMatch != etag {
				return &scim.ScimError{Status: http.StatusPreconditionFailed, Detail: "ETag mismatch"}
			}
		}

		// Load current members using tx-aware repo
		memberships, err := h.membershipRepo.FindByGroupIDTx(r.Context(), tx, group.ID)
		if err != nil {
			return err
		}
		group.Members = memberships

		for _, op := range ops {
			opMap, ok := op.(map[string]any)
			if !ok {
				continue
			}
			if err := h.applyGroupPatchOpTx(r.Context(), tx, group, wsID, opMap); err != nil {
				return err
			}
		}

		// Update group (handles version bump / optimistic lock)
		if err := h.groupRepo.UpdateTx(r.Context(), tx, group); err != nil {
			return err
		}

		// Reload memberships
		memberships, err = h.membershipRepo.FindByGroupIDTx(r.Context(), tx, group.ID)
		if err != nil {
			return err
		}
		group.Members = memberships

		updatedGroup = group
		return nil
	})

	if err != nil {
		var se *scim.ScimError
		if errors.As(err, &se) {
			scim.WriteScimError(w, se)
			return
		}
		if errors.Is(err, repository.ErrOptimisticLock) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed"))
			return
		}
		slog.Error("patch group failed", "error", err)
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update group"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)

	baseURL := buildBaseURL(r)
	response := scim.GroupToScimResponse(updatedGroup, baseURL)

	w.Header().Set("Content-Location", baseURL+"/Groups/"+updatedGroup.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", updatedGroup.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *GroupHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Group not found"))
		return
	}

	group, err := h.groupRepo.FindByIDAndWorkspaceID(r.Context(), groupID, wsID)
	if err != nil || group == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Group not found"))
		return
	}

	// Delete memberships where this group is a member of another group
	if err := h.membershipRepo.DeleteByMemberValue(r.Context(), groupID); err != nil {
		slog.Error("failed to delete memberships by member value", "error", err)
	}

	// Delete group's own memberships
	if err := h.membershipRepo.DeleteByGroupID(r.Context(), groupID); err != nil {
		slog.Error("failed to delete group memberships", "error", err)
	}

	if err := h.groupRepo.Delete(r.Context(), groupID, wsID); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to delete group"))
		return
	}

	h.touchWorkspace(r.Context(), wsID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *GroupHandler) SearchGroups(w http.ResponseWriter, r *http.Request) {
	h.ListGroups(w, r)
}

func (h *GroupHandler) applyGroupPatchOp(ctx context.Context, group *model.ScimGroup, wsID uuid.UUID, op map[string]any) error {
	opType := strings.ToLower(fmt.Sprintf("%v", op["op"]))
	path, _ := op["path"].(string)
	value := op["value"]

	switch opType {
	case "add":
		return h.applyGroupAdd(ctx, group, wsID, path, value)
	case "replace":
		return h.applyGroupReplace(ctx, group, wsID, path, value)
	case "remove":
		return h.applyGroupRemove(ctx, group, path, value)
	default:
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Unsupported PATCH op: " + opType}
	}
}

func (h *GroupHandler) applyGroupAdd(ctx context.Context, group *model.ScimGroup, wsID uuid.UUID, path string, value any) error {
	if path == "members" || path == "" {
		members := extractMembersPayload(value, true)
		return h.addMissingMembers(ctx, group, wsID, members)
	}
	if path == "displayName" {
		if s, ok := value.(string); ok {
			group.DisplayName = s
		}
	}
	return nil
}

func (h *GroupHandler) applyGroupReplace(ctx context.Context, group *model.ScimGroup, wsID uuid.UUID, path string, value any) error {
	if path == "members" {
		members := extractMembersPayload(value, false)
		return h.replaceMembers(ctx, group, wsID, members)
	}
	if path == "displayName" {
		if s, ok := value.(string); ok {
			return h.updateDisplayName(ctx, group, wsID, s)
		}
		return nil
	}
	if path == "externalId" {
		if value != nil {
			s := fmt.Sprintf("%v", value)
			group.ExternalID = &s
		} else {
			group.ExternalID = nil
		}
		return nil
	}
	if path == "" {
		if valueMap, ok := value.(map[string]any); ok {
			return h.applyReplaceValueMap(ctx, group, wsID, valueMap)
		}
	}
	return nil
}

func (h *GroupHandler) applyGroupRemove(ctx context.Context, group *model.ScimGroup, path string, value any) error {
	if path == "members" {
		// Remove all members
		if err := h.membershipRepo.DeleteByGroupID(ctx, group.ID); err != nil {
			return err
		}
		group.Members = nil
		return nil
	}
	if strings.HasPrefix(path, "members[") {
		filterExpr := path[8 : len(path)-1]
		targetValue := extractFilterValue(filterExpr)
		if targetValue != "" {
			targetUUID, err := uuid.Parse(targetValue)
			if err == nil {
				if err := h.membershipRepo.DeleteByGroupIDAndMemberValues(ctx, group.ID, []uuid.UUID{targetUUID}); err != nil {
					return err
				}
				// Remove from in-memory
				filtered := make([]model.ScimGroupMembership, 0, len(group.Members))
				for _, m := range group.Members {
					if m.MemberValue != targetUUID {
						filtered = append(filtered, m)
					}
				}
				group.Members = filtered
			}
		}
		return nil
	}
	// Remove by value list
	if rawList, ok := value.([]any); ok {
		for _, item := range rawList {
			if memberMap, ok := item.(map[string]any); ok {
				memberValue, _ := memberMap["value"].(string)
				if memberValue != "" {
					memberUUID, err := uuid.Parse(memberValue)
					if err == nil {
						if err := h.membershipRepo.DeleteByGroupIDAndMemberValues(ctx, group.ID, []uuid.UUID{memberUUID}); err != nil {
							slog.Error("failed to remove member", "error", err)
						}
						filtered := make([]model.ScimGroupMembership, 0, len(group.Members))
						for _, m := range group.Members {
							if m.MemberValue != memberUUID {
								filtered = append(filtered, m)
							}
						}
						group.Members = filtered
					}
				}
			}
		}
	}
	return nil
}

func (h *GroupHandler) applyReplaceValueMap(ctx context.Context, group *model.ScimGroup, wsID uuid.UUID, valueMap map[string]any) error {
	if dn, ok := valueMap["displayName"]; ok {
		if s, ok := dn.(string); ok {
			if err := h.updateDisplayName(ctx, group, wsID, s); err != nil {
				return err
			}
		}
	}
	if extID, ok := valueMap["externalId"]; ok {
		if extID != nil {
			s := fmt.Sprintf("%v", extID)
			group.ExternalID = &s
		} else {
			group.ExternalID = nil
		}
	}
	if membersRaw, ok := valueMap["members"]; ok {
		members := extractMembersPayload(membersRaw, false)
		return h.replaceMembers(ctx, group, wsID, members)
	}
	return nil
}

func (h *GroupHandler) updateDisplayName(ctx context.Context, group *model.ScimGroup, wsID uuid.UUID, newName string) error {
	if group.DisplayName != newName {
		existing, err := h.groupRepo.FindByDisplayNameAndWorkspaceID(ctx, newName, wsID)
		if err != nil {
			return err
		}
		if existing != nil {
			return &scim.ScimError{Status: 409, ScimType: "uniqueness",
				Detail: "Group with displayName '" + newName + "' already exists"}
		}
	}
	group.DisplayName = newName
	return nil
}

func (h *GroupHandler) addMissingMembers(ctx context.Context, group *model.ScimGroup, wsID uuid.UUID, members []map[string]any) error {
	for _, member := range members {
		memberValue, _ := member["value"].(string)
		if memberValue == "" {
			continue
		}
		// Check if already exists
		alreadyExists := false
		for _, existing := range group.Members {
			if existing.MemberValue.String() == memberValue {
				alreadyExists = true
				break
			}
		}
		if alreadyExists {
			continue
		}
		if err := h.addMember(ctx, group.ID, wsID, member); err != nil {
			return err
		}
		// Reload members
		memberships, _ := h.membershipRepo.FindByGroupID(ctx, group.ID)
		group.Members = memberships
	}
	return nil
}

func (h *GroupHandler) replaceMembers(ctx context.Context, group *model.ScimGroup, wsID uuid.UUID, members []map[string]any) error {
	if err := h.membershipRepo.DeleteByGroupID(ctx, group.ID); err != nil {
		return err
	}
	group.Members = nil
	for _, member := range members {
		if err := h.addMember(ctx, group.ID, wsID, member); err != nil {
			return err
		}
	}
	memberships, _ := h.membershipRepo.FindByGroupID(ctx, group.ID)
	group.Members = memberships
	return nil
}

// -- Transactional variants --

func (h *GroupHandler) addMemberTx(ctx context.Context, tx jdbc.Executor, groupID, wsID uuid.UUID, memberMap map[string]any) error {
	memberValue, _ := memberMap["value"].(string)
	if memberValue == "" {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Member value is required"}
	}

	memberUUID, err := uuid.Parse(memberValue)
	if err != nil {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue",
			Detail: "Invalid member value (must be UUID): " + memberValue}
	}

	memberType := "User"
	if t, ok := memberMap["type"].(string); ok && t != "" {
		if !strings.EqualFold(t, "User") && !strings.EqualFold(t, "Group") {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue",
				Detail: "Invalid member type: " + t}
		}
		if strings.EqualFold(t, "Group") {
			memberType = "Group"
		}
	}

	display, _ := memberMap["display"].(string)

	// Resolve display name for User members
	if strings.EqualFold(memberType, "User") {
		user, err := h.userRepo.FindByIDAndWorkspaceIDTx(ctx, tx, memberUUID, wsID)
		if err != nil || user == nil {
			return &scim.ScimError{Status: 404, ScimType: "invalidValue",
				Detail: "User not found: " + memberValue}
		}
		if display == "" {
			if user.DisplayName != nil && *user.DisplayName != "" {
				display = *user.DisplayName
			} else {
				display = user.UserName
			}
		}
	}

	membership := model.ScimGroupMembership{
		ID:          uuid.New(),
		GroupID:     groupID,
		WorkspaceID: wsID,
		MemberValue: memberUUID,
		MemberType:  &memberType,
		Display:     &display,
	}

	return h.membershipRepo.CreateBatchTx(ctx, tx, []model.ScimGroupMembership{membership})
}

func (h *GroupHandler) replaceMembersTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, members []map[string]any) error {
	if err := h.membershipRepo.DeleteByGroupIDTx(ctx, tx, group.ID); err != nil {
		return err
	}
	group.Members = nil
	for _, member := range members {
		if err := h.addMemberTx(ctx, tx, group.ID, wsID, member); err != nil {
			return err
		}
	}
	memberships, err := h.membershipRepo.FindByGroupIDTx(ctx, tx, group.ID)
	if err != nil {
		return err
	}
	group.Members = memberships
	return nil
}

func (h *GroupHandler) applyGroupPatchOpTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, op map[string]any) error {
	opType := strings.ToLower(fmt.Sprintf("%v", op["op"]))
	path, _ := op["path"].(string)
	value := op["value"]

	switch opType {
	case "add":
		return h.applyGroupAddTx(ctx, tx, group, wsID, path, value)
	case "replace":
		return h.applyGroupReplaceTx(ctx, tx, group, wsID, path, value)
	case "remove":
		return h.applyGroupRemoveTx(ctx, tx, group, path, value)
	default:
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Unsupported PATCH op: " + opType}
	}
}

func (h *GroupHandler) applyGroupAddTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, path string, value any) error {
	if path == "members" || path == "" {
		members := extractMembersPayload(value, true)
		return h.addMissingMembersTx(ctx, tx, group, wsID, members)
	}
	if path == "displayName" {
		if s, ok := value.(string); ok {
			group.DisplayName = s
		}
	}
	return nil
}

func (h *GroupHandler) applyGroupReplaceTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, path string, value any) error {
	if path == "members" {
		members := extractMembersPayload(value, false)
		return h.replaceMembersTx(ctx, tx, group, wsID, members)
	}
	if path == "displayName" {
		if s, ok := value.(string); ok {
			return h.updateDisplayNameTx(ctx, tx, group, wsID, s)
		}
		return nil
	}
	if path == "externalId" {
		if value != nil {
			s := fmt.Sprintf("%v", value)
			group.ExternalID = &s
		} else {
			group.ExternalID = nil
		}
		return nil
	}
	if path == "" {
		if valueMap, ok := value.(map[string]any); ok {
			return h.applyReplaceValueMapTx(ctx, tx, group, wsID, valueMap)
		}
	}
	return nil
}

func (h *GroupHandler) applyGroupRemoveTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, path string, value any) error {
	if path == "members" {
		if err := h.membershipRepo.DeleteByGroupIDTx(ctx, tx, group.ID); err != nil {
			return err
		}
		group.Members = nil
		return nil
	}
	if strings.HasPrefix(path, "members[") {
		filterExpr := path[8 : len(path)-1]
		targetValue := extractFilterValue(filterExpr)
		if targetValue != "" {
			targetUUID, err := uuid.Parse(targetValue)
			if err == nil {
				if err := h.membershipRepo.DeleteByGroupIDAndMemberValuesTx(ctx, tx, group.ID, []uuid.UUID{targetUUID}); err != nil {
					return err
				}
				filtered := make([]model.ScimGroupMembership, 0, len(group.Members))
				for _, m := range group.Members {
					if m.MemberValue != targetUUID {
						filtered = append(filtered, m)
					}
				}
				group.Members = filtered
			}
		}
		return nil
	}
	if rawList, ok := value.([]any); ok {
		for _, item := range rawList {
			if memberMap, ok := item.(map[string]any); ok {
				memberValue, _ := memberMap["value"].(string)
				if memberValue != "" {
					memberUUID, err := uuid.Parse(memberValue)
					if err == nil {
						if err := h.membershipRepo.DeleteByGroupIDAndMemberValuesTx(ctx, tx, group.ID, []uuid.UUID{memberUUID}); err != nil {
							slog.Error("failed to remove member", "error", err)
						}
						filtered := make([]model.ScimGroupMembership, 0, len(group.Members))
						for _, m := range group.Members {
							if m.MemberValue != memberUUID {
								filtered = append(filtered, m)
							}
						}
						group.Members = filtered
					}
				}
			}
		}
	}
	return nil
}

func (h *GroupHandler) applyReplaceValueMapTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, valueMap map[string]any) error {
	if dn, ok := valueMap["displayName"]; ok {
		if s, ok := dn.(string); ok {
			if err := h.updateDisplayNameTx(ctx, tx, group, wsID, s); err != nil {
				return err
			}
		}
	}
	if extID, ok := valueMap["externalId"]; ok {
		if extID != nil {
			s := fmt.Sprintf("%v", extID)
			group.ExternalID = &s
		} else {
			group.ExternalID = nil
		}
	}
	if membersRaw, ok := valueMap["members"]; ok {
		members := extractMembersPayload(membersRaw, false)
		return h.replaceMembersTx(ctx, tx, group, wsID, members)
	}
	return nil
}

func (h *GroupHandler) updateDisplayNameTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, newName string) error {
	if group.DisplayName != newName {
		existing, err := h.groupRepo.FindByDisplayNameAndWorkspaceIDTx(ctx, tx, newName, wsID)
		if err != nil {
			return err
		}
		if existing != nil {
			return &scim.ScimError{Status: 409, ScimType: "uniqueness",
				Detail: "Group with displayName '" + newName + "' already exists"}
		}
	}
	group.DisplayName = newName
	return nil
}

func (h *GroupHandler) addMissingMembersTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, members []map[string]any) error {
	for _, member := range members {
		memberValue, _ := member["value"].(string)
		if memberValue == "" {
			continue
		}
		alreadyExists := false
		for _, existing := range group.Members {
			if existing.MemberValue.String() == memberValue {
				alreadyExists = true
				break
			}
		}
		if alreadyExists {
			continue
		}
		if err := h.addMemberTx(ctx, tx, group.ID, wsID, member); err != nil {
			return err
		}
		memberships, err := h.membershipRepo.FindByGroupIDTx(ctx, tx, group.ID)
		if err != nil {
			return err
		}
		group.Members = memberships
	}
	return nil
}

func (h *GroupHandler) addMember(ctx context.Context, groupID, wsID uuid.UUID, memberMap map[string]any) error {
	memberValue, _ := memberMap["value"].(string)
	if memberValue == "" {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Member value is required"}
	}

	memberUUID, err := uuid.Parse(memberValue)
	if err != nil {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue",
			Detail: "Invalid member value (must be UUID): " + memberValue}
	}

	memberType := "User"
	if t, ok := memberMap["type"].(string); ok && t != "" {
		if !strings.EqualFold(t, "User") && !strings.EqualFold(t, "Group") {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue",
				Detail: "Invalid member type: " + t}
		}
		if strings.EqualFold(t, "Group") {
			memberType = "Group"
		}
	}

	display, _ := memberMap["display"].(string)

	// Resolve display name for User members
	if strings.EqualFold(memberType, "User") {
		user, err := h.userRepo.FindByIDAndWorkspaceID(ctx, memberUUID, wsID)
		if err != nil || user == nil {
			return &scim.ScimError{Status: 404, ScimType: "invalidValue",
				Detail: "User not found: " + memberValue}
		}
		if display == "" {
			if user.DisplayName != nil && *user.DisplayName != "" {
				display = *user.DisplayName
			} else {
				display = user.UserName
			}
		}
	}

	membership := model.ScimGroupMembership{
		ID:          uuid.New(),
		GroupID:     groupID,
		WorkspaceID: wsID,
		MemberValue: memberUUID,
		MemberType:  &memberType,
		Display:     &display,
	}

	return h.membershipRepo.CreateBatch(ctx, []model.ScimGroupMembership{membership})
}

func (h *GroupHandler) touchWorkspace(ctx context.Context, wsID uuid.UUID) {
	if err := h.workspaceRepo.TouchUpdatedAt(ctx, wsID); err != nil {
		slog.Error("failed to touch workspace", "error", err)
	}
}

func extractMembersPayload(value any, allowEnvelope bool) []map[string]any {
	if rawList, ok := value.([]any); ok {
		result := make([]map[string]any, 0, len(rawList))
		for _, item := range rawList {
			if m, ok := item.(map[string]any); ok {
				result = append(result, m)
			}
		}
		return result
	}
	if rawMap, ok := value.(map[string]any); ok {
		if allowEnvelope {
			if members, ok := rawMap["members"]; ok {
				return extractMembersPayload(members, false)
			}
		}
		return []map[string]any{rawMap}
	}
	return nil
}

func extractFilterValue(filterExpr string) string {
	matches := memberValueFilterRe.FindStringSubmatch(filterExpr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
