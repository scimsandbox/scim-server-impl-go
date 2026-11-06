package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
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

var (
	memberValueFilterRe = regexp.MustCompile(`(?i)\bvalue\s+eq\s+"([^"]+)"`)
	memberRefFilterRe   = regexp.MustCompile(`(?i)\$ref\s+eq\s+"([^"]+)"`)
)

// resolveMemberID extracts a canonical member identifier from a Group.members object,
// using "value" when present or falling back to version-agnostic $ref URI extraction (RFC 7643 §2.4).
func resolveMemberID(memberMap map[string]any) string {
	if memberMap == nil {
		return ""
	}
	if mv, ok := memberMap["value"].(string); ok && strings.TrimSpace(mv) != "" {
		trimmed := strings.TrimSpace(mv)
		if mu, err := uuid.Parse(trimmed); err == nil {
			return mu.String()
		}
		return trimmed
	}
	if refStr, ok := memberMap["$ref"].(string); ok && strings.TrimSpace(refStr) != "" {
		return scim.ExtractUUIDFromRef(refStr)
	}
	return ""
}

// checkMemberValueRefConflict validates the types of "value" and "$ref" on a Group.members
// entry and rejects conflicting resource IDs when both are provided.
func checkMemberValueRefConflict(memberMap map[string]any) error {
	if memberMap == nil {
		return nil
	}
	var memberValue string
	if rawVal, exists := memberMap["value"]; exists && rawVal != nil {
		s, ok := rawVal.(string)
		if !ok {
			return &scim.ScimError{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "Member value must be a string"}
		}
		memberValue = strings.TrimSpace(s)
	}
	var refStr string
	if rawRef, exists := memberMap["$ref"]; exists && rawRef != nil {
		s, ok := rawRef.(string)
		if !ok {
			return &scim.ScimError{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "Member $ref must be a string"}
		}
		refStr = strings.TrimSpace(s)
	}
	if memberValue != "" && refStr != "" {
		if refUUID := scim.ExtractUUIDFromRef(refStr); refUUID != "" && !strings.EqualFold(memberValue, refUUID) {
			return &scim.ScimError{Status: http.StatusBadRequest, ScimType: "invalidValue", Detail: "Member value and $ref refer to different resource IDs"}
		}
	}
	return nil
}

type GroupHandler struct {
	groupRepo      *repository.GroupRepository
	membershipRepo *repository.MembershipRepository
	userRepo       *repository.UserRepository
	workspaceRepo  *repository.WorkspaceRepository
	asyncEventRepo repository.AsyncEventRepo
}

func NewGroupHandler(
	groupRepo *repository.GroupRepository,
	membershipRepo *repository.MembershipRepository,
	userRepo *repository.UserRepository,
	workspaceRepo *repository.WorkspaceRepository,
	asyncEventRepo ...repository.AsyncEventRepo,
) *GroupHandler {
	var ar repository.AsyncEventRepo
	if len(asyncEventRepo) > 0 {
		ar = asyncEventRepo[0]
	}
	return &GroupHandler{
		groupRepo:      groupRepo,
		membershipRepo: membershipRepo,
		userRepo:       userRepo,
		workspaceRepo:  workspaceRepo,
		asyncEventRepo: ar,
	}
}

func parseGroupExternalID(raw any, exists bool) (*string, error) {
	if !exists || raw == nil {
		return nil, nil
	}
	s, ok := raw.(string)
	if !ok {
		return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "Attribute 'externalId' must be a string")
	}
	norm := scim.NormalizeNFC(s)
	return &norm, nil
}

func strPtrEq(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func cloneGroupStrPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}

func groupMembersEqual(a, b []model.ScimGroupMembership) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	setA := make(map[string]int, len(a))
	for _, m := range a {
		mt := ""
		if m.MemberType != nil && *m.MemberType != "" {
			mt = strings.ToLower(*m.MemberType)
		}
		key := m.MemberValue.String() + "|" + mt
		setA[key]++
	}
	for _, m := range b {
		mt := ""
		if m.MemberType != nil && *m.MemberType != "" {
			mt = strings.ToLower(*m.MemberType)
		}
		key := m.MemberValue.String() + "|" + mt
		if setA[key] <= 0 {
			return false
		}
		setA[key]--
	}
	return true
}

func isGroupDisplayNameConflict(err error) bool {
	var uniqueErr jdbc.UniqueViolationError
	if !errors.As(err, &uniqueErr) {
		return false
	}
	return strings.Contains(strings.ToLower(uniqueErr.Constraint), "display_name")
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

	rawDN, hasDN := input["displayName"]
	displayName, okDN := rawDN.(string)
	displayName = scim.NormalizeNFC(displayName)
	if !hasDN || !okDN || displayName == "" {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "displayName is required"))
		return
	}

	rawExt, hasExt := input["externalId"]
	if _, err := parseGroupExternalID(rawExt, hasExt); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "POST",
			ResourceType: "Group",
			Status:       model.AsyncStatusPending,
			SetPayload:   &baseURL,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", prefHeader)
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		runAsyncWorker(h.asyncEventRepo, baseURL, txnID, "Group", nil, "POST", func(workerCtx context.Context) (*uuid.UUID, string, error) {
			group, err := h.executeCreateGroup(workerCtx, wsID, input)
			if err != nil {
				return nil, "", err
			}
			resp := scim.GroupToScimResponse(group, baseURL)
			setStr, err := buildSETJson(baseURL, txnID, "Group", group.ID, "POST", resp)
			if err != nil {
				return &group.ID, "", err
			}
			return &group.ID, setStr, nil
		})
		return
	}

	group, err := h.executeCreateGroup(r.Context(), wsID, input)
	if err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	baseURL := buildBaseURL(r)
	response := scim.GroupToScimResponse(group, baseURL)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	resourceURL := baseURL + "/Groups/" + group.ID.String()
	w.Header().Set("Location", resourceURL)
	w.Header().Set("Content-Location", resourceURL)
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", group.Version))
	writeJSON(w, http.StatusCreated, response)
}

func (h *GroupHandler) executeCreateGroup(ctx context.Context, wsID uuid.UUID, input map[string]any) (*model.ScimGroup, error) {
	if h.groupRepo == nil {
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	rawDN, hasDN := input["displayName"]
	displayName, okDN := rawDN.(string)
	displayName = scim.NormalizeNFC(displayName)
	if !hasDN || !okDN || displayName == "" {
		return nil, scim.NewScimError(http.StatusBadRequest, "invalidValue", "displayName is required")
	}

	rawExt, hasExt := input["externalId"]
	extIDPtr, err := parseGroupExternalID(rawExt, hasExt)
	if err != nil {
		return nil, err
	}

	var createdGroup *model.ScimGroup
	err = jdbc.InTransaction(ctx, func(tx jdbc.Tx) error {
		existing, err := h.groupRepo.FindByDisplayNameAndWorkspaceIDTx(ctx, tx, displayName, wsID)
		if err != nil {
			return scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
		}
		if existing != nil {
			return scim.NewScimError(http.StatusConflict, "uniqueness",
				"Group with displayName '"+displayName+"' already exists")
		}

		group := &model.ScimGroup{
			ID:           uuid.New(),
			WorkspaceID:  wsID,
			DisplayName:  displayName,
			ExternalID:   extIDPtr,
			CreatedAt:    time.Now().UTC(),
			LastModified: time.Now().UTC(),
			Version:      0,
		}

		if err := h.groupRepo.CreateTx(ctx, tx, group); err != nil {
			if isGroupDisplayNameConflict(err) {
				return scim.NewScimError(http.StatusConflict, "uniqueness",
					"Group with displayName '"+displayName+"' already exists")
			}
			return scim.NewScimError(http.StatusInternalServerError, "", "Failed to create group")
		}

		if members, ok := input["members"].([]any); ok {
			seenMembers := make(map[string]bool, len(members))
			for _, m := range members {
				if memberMap, ok := m.(map[string]any); ok {
					if err := checkMemberValueRefConflict(memberMap); err != nil {
						return err
					}
					if mv := resolveMemberID(memberMap); mv != "" {
						if seenMembers[mv] {
							continue
						}
						seenMembers[mv] = true
					}
					if err := h.addMemberTx(ctx, tx, group.ID, wsID, memberMap); err != nil {
						return err
					}
				}
			}
		}

		if h.membershipRepo != nil {
			memberships, _ := h.membershipRepo.FindByGroupIDTx(ctx, tx, group.ID)
			group.Members = memberships
		}
		createdGroup = group
		return nil
	})
	if err != nil {
		return nil, err
	}

	h.touchWorkspace(ctx, wsID)
	return createdGroup, nil
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

	// If-None-Match (RFC 7232 §3.2)
	if ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match")); ifNoneMatch != "" && checkETagMatch(ifNoneMatch, group.Version) {
		w.WriteHeader(http.StatusNotModified)
		return
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

	pag, scimErr := parsePagination(r.URL.Query(), nil, wsID, 100)
	if scimErr != nil {
		scim.WriteScimError(w, scimErr)
		return
	}
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

	if pag.Count == 0 {
		listResponse := buildListResponse(pag, wsID, int(totalCount), []map[string]any{})
		writeJSON(w, http.StatusOK, listResponse)
		return
	}

	groups, err := h.groupRepo.List(r.Context(), wsID, whereClause, filterArgs, sortColumn, sortDir, pag.Offset, pag.Count)
	if err != nil {
		slog.Error("list groups failed", "error", err)
		scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
		return
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

	listResponse := buildListResponse(pag, wsID, int(totalCount), resources)
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

	rawDN, hasDN := input["displayName"]
	displayName, okDN := rawDN.(string)
	displayName = scim.NormalizeNFC(displayName)
	if !hasDN || !okDN || displayName == "" {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue", "displayName is required"))
		return
	}

	rawExt, hasExt := input["externalId"]
	if _, err := parseGroupExternalID(rawExt, hasExt); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()
		ifMatchHdr := r.Header.Get("If-Match")

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "PUT",
			ResourceType: "Group",
			ResourceID:   &groupID,
			Status:       model.AsyncStatusPending,
			SetPayload:   &baseURL,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", prefHeader)
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		runAsyncWorker(h.asyncEventRepo, baseURL, txnID, "Group", &groupID, "PUT", func(workerCtx context.Context) (*uuid.UUID, string, error) {
			updatedGroup, err := h.executeReplaceGroup(workerCtx, wsID, groupID, input, ifMatchHdr)
			if err != nil {
				return &groupID, "", err
			}
			resp := scim.GroupToScimResponse(updatedGroup, baseURL)
			setStr, err := buildSETJson(baseURL, txnID, "Group", groupID, "PUT", resp)
			if err != nil {
				return &groupID, "", err
			}
			return &groupID, setStr, nil
		})
		return
	}

	updatedGroup, err := h.executeReplaceGroup(r.Context(), wsID, groupID, input, r.Header.Get("If-Match"))
	if err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	baseURL := buildBaseURL(r)
	response := scim.GroupToScimResponse(updatedGroup, baseURL)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	w.Header().Set("Content-Location", baseURL+"/Groups/"+updatedGroup.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", updatedGroup.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *GroupHandler) executeReplaceGroup(ctx context.Context, wsID, groupID uuid.UUID, input map[string]any, ifMatch string) (*model.ScimGroup, error) {
	if h.groupRepo == nil {
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	var displayName string
	var updatedGroup *model.ScimGroup
	err := jdbc.InTransaction(ctx, func(tx jdbc.Tx) error {
		group, err := h.groupRepo.FindByIDAndWorkspaceIDTx(ctx, tx, groupID, wsID)
		if err != nil || group == nil {
			return &scim.ScimError{Status: http.StatusNotFound, Detail: "Group not found"}
		}

		// If-Match (RFC 7232 §3.1 / RFC 7644 §3.14 wildcard support)
		if !checkETagMatch(ifMatch, group.Version) {
			return &scim.ScimError{Status: http.StatusPreconditionFailed, Detail: "ETag mismatch"}
		}

		rawDN, hasDN := input["displayName"]
		var okDN bool
		displayName, okDN = rawDN.(string)
		displayName = scim.NormalizeNFC(displayName)
		if !hasDN || !okDN || displayName == "" {
			return scim.NewScimError(http.StatusBadRequest, "invalidValue", "displayName is required")
		}

		rawExt, hasExt := input["externalId"]
		extIDPtr, err := parseGroupExternalID(rawExt, hasExt)
		if err != nil {
			return err
		}

		// Uniqueness check
		if displayName != group.DisplayName {
			existing, err := h.groupRepo.FindByDisplayNameAndWorkspaceIDTx(ctx, tx, displayName, wsID)
			if err != nil {
				return err
			}
			if existing != nil && existing.ID != group.ID {
				return &scim.ScimError{Status: http.StatusConflict, ScimType: "uniqueness",
					Detail: "Group with displayName '" + displayName + "' already exists"}
			}
		}

		// GRP_21: RFC 7643 §4.2 - Group member sub-attributes 'value' and 'type' are immutable
		if err := h.checkMemberTypeImmutabilityTx(ctx, tx, group.ID, input["members"]); err != nil {
			return err
		}

		group.DisplayName = displayName
		group.ExternalID = extIDPtr

		// Clear existing members
		if err := h.membershipRepo.DeleteByGroupIDTx(ctx, tx, group.ID); err != nil {
			slog.Error("failed to clear memberships", "error", err)
			return err
		}

		// Re-add members inside transaction (deduplicating repeated entries)
		if members, ok := input["members"].([]any); ok {
			seenMembers := make(map[string]bool, len(members))
			for _, m := range members {
				if memberMap, ok := m.(map[string]any); ok {
					if err := checkMemberValueRefConflict(memberMap); err != nil {
						return err
					}
					if mv := resolveMemberID(memberMap); mv != "" {
						if seenMembers[mv] {
							continue
						}
						seenMembers[mv] = true
					}
					if err := h.addMemberTx(ctx, tx, group.ID, wsID, memberMap); err != nil {
						return err
					}
				}
			}
		}

		group.LastModified = time.Now().UTC()
		// Update group (also handles version bump / optimistic lock check)
		if err := h.groupRepo.UpdateTx(ctx, tx, group); err != nil {
			return err
		}

		// Reload memberships into group
		memberships, err := h.membershipRepo.FindByGroupIDTx(ctx, tx, group.ID)
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
			return nil, se
		}
		if errors.Is(err, repository.ErrOptimisticLock) {
			return nil, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed")
		}
		if isGroupDisplayNameConflict(err) {
			return nil, scim.NewScimError(http.StatusConflict, "uniqueness",
				"Group with displayName '"+displayName+"' already exists")
		}
		slog.Error("replace group failed", "error", err)
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update group")
	}

	h.touchWorkspace(ctx, wsID)
	return updatedGroup, nil
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

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()
		ifMatchHdr := r.Header.Get("If-Match")

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "PATCH",
			ResourceType: "Group",
			ResourceID:   &groupID,
			Status:       model.AsyncStatusPending,
			SetPayload:   &baseURL,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", prefHeader)
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		runAsyncWorker(h.asyncEventRepo, baseURL, txnID, "Group", &groupID, "PATCH", func(workerCtx context.Context) (*uuid.UUID, string, error) {
			opMaps := make([]map[string]any, 0, len(ops))
			for _, op := range ops {
				m, ok := op.(map[string]any)
				if !ok {
					return &groupID, "", &scim.ScimError{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "Invalid PATCH operation"}
				}
				opMaps = append(opMaps, m)
			}
			updatedGroup, err := h.executePatchGroup(workerCtx, wsID, groupID, opMaps, ifMatchHdr)
			if err != nil {
				return &groupID, "", err
			}
			resp := scim.GroupToScimResponse(updatedGroup, baseURL)
			patchPaths := extractModifiedPatchPaths(opMaps)
			setStr, err := buildSETJson(baseURL, txnID, "Group", groupID, "PATCH", resp, patchPaths...)
			if err != nil {
				return &groupID, "", err
			}
			return &groupID, setStr, nil
		})
		return
	}

	opMaps := make([]map[string]any, 0, len(ops))
	for _, op := range ops {
		m, ok := op.(map[string]any)
		if !ok {
			scim.WriteScimError(w, &scim.ScimError{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "Invalid PATCH operation"})
			return
		}
		opMaps = append(opMaps, m)
	}

	updatedGroup, err := h.executePatchGroup(r.Context(), wsID, groupID, opMaps, r.Header.Get("If-Match"))
	if err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	baseURL := buildBaseURL(r)
	response := scim.GroupToScimResponse(updatedGroup, baseURL)

	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")
	response = applyAttributeProjection(response, attrs, excludedAttrs)

	w.Header().Set("Content-Location", baseURL+"/Groups/"+updatedGroup.ID.String())
	w.Header().Set("ETag", fmt.Sprintf("W/\"%d\"", updatedGroup.Version))
	writeJSON(w, http.StatusOK, response)
}

func (h *GroupHandler) executePatchGroup(ctx context.Context, wsID, groupID uuid.UUID, ops []map[string]any, ifMatch string) (*model.ScimGroup, error) {
	if h.groupRepo == nil {
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	var updatedGroup *model.ScimGroup
	changed := false
	err := jdbc.InTransaction(ctx, func(tx jdbc.Tx) error {
		group, err := h.groupRepo.FindByIDAndWorkspaceIDTx(ctx, tx, groupID, wsID)
		if err != nil || group == nil {
			return &scim.ScimError{Status: http.StatusNotFound, Detail: "Group not found"}
		}

		// If-Match (RFC 7232 §3.1 / RFC 7644 §3.14 wildcard support)
		if !checkETagMatch(ifMatch, group.Version) {
			return &scim.ScimError{Status: http.StatusPreconditionFailed, Detail: "ETag mismatch"}
		}

		// Load current members using tx-aware repo
		memberships, err := h.membershipRepo.FindByGroupIDTx(ctx, tx, group.ID)
		if err != nil {
			return err
		}
		group.Members = memberships

		beforeDN := group.DisplayName
		beforeExt := cloneGroupStrPtr(group.ExternalID)
		beforeMembers := append([]model.ScimGroupMembership(nil), memberships...)

		for _, opMap := range ops {
			if err := h.applyGroupPatchOpTx(ctx, tx, group, wsID, opMap); err != nil {
				return err
			}
		}

		// Reload memberships
		afterMembers, err := h.membershipRepo.FindByGroupIDTx(ctx, tx, group.ID)
		if err != nil {
			return err
		}

		if group.DisplayName != beforeDN || !strPtrEq(group.ExternalID, beforeExt) || !groupMembersEqual(beforeMembers, afterMembers) {
			changed = true
			group.LastModified = time.Now().UTC()
			// Update group (handles version bump / optimistic lock)
			if err := h.groupRepo.UpdateTx(ctx, tx, group); err != nil {
				return err
			}
		}

		group.Members = afterMembers
		updatedGroup = group
		return nil
	})
	if err != nil {
		var se *scim.ScimError
		if errors.As(err, &se) {
			return nil, se
		}
		if errors.Is(err, repository.ErrOptimisticLock) {
			return nil, scim.NewScimError(http.StatusPreconditionFailed, "", "Resource changed")
		}
		if isGroupDisplayNameConflict(err) {
			return nil, scim.NewScimError(http.StatusConflict, "uniqueness", "Group displayName already exists")
		}
		slog.Error("patch group failed", "error", err)
		return nil, scim.NewScimError(http.StatusInternalServerError, "", "Failed to update group")
	}

	if changed {
		h.touchWorkspace(ctx, wsID)
	}
	return updatedGroup, nil
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

	if execAsync, prefHeader := shouldExecuteAsync(r); execAsync && h.asyncEventRepo != nil {
		txnID := uuid.New()
		baseURL := buildBaseURL(r)
		eventURL := baseURL + "/Events/" + txnID.String()
		ifMatchHdr := r.Header.Get("If-Match")

		event := &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "DELETE",
			ResourceType: "Group",
			ResourceID:   &groupID,
			Status:       model.AsyncStatusPending,
			SetPayload:   &baseURL,
			CreatedAt:    time.Now().UTC(),
		}
		if err := h.asyncEventRepo.Create(r.Context(), event); err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Failed to create async event"))
			return
		}

		w.Header().Set("Set-Txn", txnID.String())
		w.Header().Set("Preference-Applied", prefHeader)
		w.Header().Set("Location", eventURL)
		w.WriteHeader(http.StatusAccepted)

		runAsyncWorker(h.asyncEventRepo, baseURL, txnID, "Group", &groupID, "DELETE", func(workerCtx context.Context) (*uuid.UUID, string, error) {
			if err := h.executeDeleteGroup(workerCtx, wsID, groupID, ifMatchHdr); err != nil {
				return &groupID, "", err
			}
			setStr, err := buildSETJson(baseURL, txnID, "Group", groupID, "DELETE", nil)
			if err != nil {
				return &groupID, "", err
			}
			return &groupID, setStr, nil
		})
		return
	}

	if err := h.executeDeleteGroup(r.Context(), wsID, groupID, r.Header.Get("If-Match")); err != nil {
		scim.WriteErrorFromAny(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *GroupHandler) executeDeleteGroup(ctx context.Context, wsID, groupID uuid.UUID, ifMatch string) error {
	if h.groupRepo == nil {
		return scim.NewScimError(http.StatusInternalServerError, "", "Internal error")
	}

	group, err := h.groupRepo.FindByIDAndWorkspaceID(ctx, groupID, wsID)
	if err != nil || group == nil {
		return scim.NewScimError(http.StatusNotFound, "", "Group not found")
	}

	if !checkETagMatch(ifMatch, group.Version) {
		return scim.NewScimError(http.StatusPreconditionFailed, "", "ETag mismatch")
	}

	// Delete memberships where this group is a member of another group
	if h.membershipRepo != nil {
		if err := h.membershipRepo.DeleteByMemberValue(ctx, groupID); err != nil {
			slog.Error("failed to delete memberships by member value", "error", err)
		}

		// Delete group's own memberships
		if err := h.membershipRepo.DeleteByGroupID(ctx, groupID); err != nil {
			slog.Error("failed to delete group memberships", "error", err)
		}
	}

	if err := h.groupRepo.Delete(ctx, groupID, wsID); err != nil {
		return scim.NewScimError(http.StatusInternalServerError, "", "Failed to delete group")
	}

	h.touchWorkspace(ctx, wsID)
	return nil
}

func (h *GroupHandler) SearchGroups(w http.ResponseWriter, r *http.Request) {
	// POST /.search: parse JSON body and inject into query params for ListGroups
	var body map[string]any
	if err := readJSON(r, &body); err != nil && err != io.EOF {
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

	h.ListGroups(w, r)
}

func cleanGroupPatchPath(rawPath string) string {
	p := strings.TrimSpace(rawPath)
	prefix := strings.ToLower(scim.GroupSchemaURN) + ":"
	if strings.HasPrefix(strings.ToLower(p), prefix) {
		p = strings.TrimSpace(p[len(prefix):])
	}
	return p
}

func isGroupReadOnlyAttr(cleanPath string) bool {
	lp := strings.ToLower(strings.TrimSpace(cleanPath))
	return lp == "id" || lp == "meta" || strings.HasPrefix(lp, "meta.")
}

// validateMemberTypeImmutability enforces RFC 7643 §4.2 member 'type' immutability (GRP_21).
// If a member present in existingMemberships is included in rawMembers with a non-empty 'type'
// that differs (case-insensitively) from its existing MemberType, a 400 mutability ScimError is returned.
func validateMemberTypeImmutability(existingMemberships []model.ScimGroupMembership, rawMembers any) error {
	if len(existingMemberships) == 0 || rawMembers == nil {
		return nil
	}
	existingMemberTypes := make(map[uuid.UUID]string, len(existingMemberships))
	for _, m := range existingMemberships {
		if m.MemberType != nil && *m.MemberType != "" {
			existingMemberTypes[m.MemberValue] = *m.MemberType
		}
	}
	if len(existingMemberTypes) == 0 {
		return nil
	}

	var memberMaps []map[string]any
	switch v := rawMembers.(type) {
	case []any:
		for _, item := range v {
			if mm, ok := item.(map[string]any); ok {
				memberMaps = append(memberMaps, mm)
			}
		}
	case []map[string]any:
		memberMaps = v
	}

	for _, memberMap := range memberMaps {
		valStr := resolveMemberID(memberMap)
		if valStr == "" {
			continue
		}
		memberUUID, err := uuid.Parse(valStr)
		if err != nil {
			continue
		}
		existingType, exists := existingMemberTypes[memberUUID]
		if !exists {
			continue
		}
		newType, ok := memberMap["type"].(string)
		if !ok || newType == "" {
			continue
		}
		if !strings.EqualFold(existingType, newType) {
			return &scim.ScimError{
				Status:   http.StatusBadRequest,
				ScimType: "mutability",
				Detail:   "Group member type is immutable and cannot be changed for member: " + valStr,
			}
		}
	}
	return nil
}

func (h *GroupHandler) checkMemberTypeImmutabilityTx(ctx context.Context, tx jdbc.Executor, groupID uuid.UUID, rawMembers any) error {
	if rawMembers == nil {
		return nil
	}
	existingMemberships, err := h.membershipRepo.FindByGroupIDTx(ctx, tx, groupID)
	if err != nil {
		return err
	}
	return validateMemberTypeImmutability(existingMemberships, rawMembers)
}

// -- Transactional variants --

func (h *GroupHandler) addMemberTx(ctx context.Context, tx jdbc.Executor, groupID, wsID uuid.UUID, memberMap map[string]any) error {
	if err := checkMemberValueRefConflict(memberMap); err != nil {
		return err
	}
	memberValue := resolveMemberID(memberMap)
	if memberValue == "" {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Member value is required"}
	}

	memberUUID, err := uuid.Parse(memberValue)
	if err != nil {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue",
			Detail: "Invalid member value (must be UUID): " + memberValue}
	}

	explicitType := ""
	if rawT, exists := memberMap["type"]; exists && rawT != nil {
		t, ok := rawT.(string)
		if !ok {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Member type must be a string"}
		}
		if t != "" {
			if !strings.EqualFold(t, "User") && !strings.EqualFold(t, "Group") {
				return &scim.ScimError{Status: 400, ScimType: "invalidValue",
					Detail: "Invalid member type: " + t}
			}
			if strings.EqualFold(t, "Group") {
				explicitType = "Group"
			} else {
				explicitType = "User"
			}
		}
	}

	display, _ := memberMap["display"].(string)
	display = scim.NormalizeNFC(display)
	memberType := explicitType

	switch explicitType {
	case "User":
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
	case "Group":
		childGroup, err := h.groupRepo.FindByIDAndWorkspaceIDTx(ctx, tx, memberUUID, wsID)
		if err != nil || childGroup == nil {
			return &scim.ScimError{Status: 404, ScimType: "invalidValue",
				Detail: "Group not found: " + memberValue}
		}
		if display == "" {
			display = childGroup.DisplayName
		}
	default:
		// Type omitted: check User first, then Group within the same workspace
		user, uErr := h.userRepo.FindByIDAndWorkspaceIDTx(ctx, tx, memberUUID, wsID)
		if uErr == nil && user != nil {
			memberType = "User"
			if display == "" {
				if user.DisplayName != nil && *user.DisplayName != "" {
					display = *user.DisplayName
				} else {
					display = user.UserName
				}
			}
		} else {
			childGroup, gErr := h.groupRepo.FindByIDAndWorkspaceIDTx(ctx, tx, memberUUID, wsID)
			if gErr == nil && childGroup != nil {
				memberType = "Group"
				if display == "" {
					display = childGroup.DisplayName
				}
			} else {
				return &scim.ScimError{Status: 404, ScimType: "invalidValue",
					Detail: "Member resource not found: " + memberValue}
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
	if err := validateMemberTypeImmutability(group.Members, members); err != nil {
		return err
	}
	if err := h.membershipRepo.DeleteByGroupIDTx(ctx, tx, group.ID); err != nil {
		return err
	}
	group.Members = nil
	seen := make(map[string]bool, len(members))
	for _, member := range members {
		if err := checkMemberValueRefConflict(member); err != nil {
			return err
		}
		if mv := resolveMemberID(member); mv != "" {
			if seen[mv] {
				continue
			}
			seen[mv] = true
		}
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
	rawPath, _ := op["path"].(string)
	path := cleanGroupPatchPath(rawPath)
	value := op["value"]

	if isGroupReadOnlyAttr(path) {
		return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Attribute '" + path + "' is readOnly and cannot be modified"}
	}

	switch opType {
	case "add":
		if value == nil {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "PATCH add operation must contain a 'value' member"}
		}
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
	lp := strings.ToLower(path)
	if lp == "members" {
		members := extractMembersPayload(value, true)
		return h.addMissingMembersTx(ctx, tx, group, wsID, members)
	}
	if lp == "displayname" {
		s, ok := value.(string)
		s = scim.NormalizeNFC(s)
		if !ok || s == "" {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'displayName' must be a non-empty string"}
		}
		return h.updateDisplayNameTx(ctx, tx, group, wsID, s)
	}
	if lp == "externalid" {
		s, ok := value.(string)
		if !ok {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'externalId' must be a string"}
		}
		norm := scim.NormalizeNFC(s)
		group.ExternalID = &norm
		return nil
	}
	if path == "" {
		if valueMap, ok := value.(map[string]any); ok {
			_, hasMemberValue := valueMap["value"]
			_, hasMemberRef := valueMap["$ref"]
			if (hasMemberValue || hasMemberRef) && len(valueMap) <= 4 {
				if _, hasDN := valueMap["displayName"]; !hasDN {
					if _, hasMembers := valueMap["members"]; !hasMembers {
						return h.addMissingMembersTx(ctx, tx, group, wsID, []map[string]any{valueMap})
					}
				}
			}
			return h.applyAddValueMapTx(ctx, tx, group, wsID, valueMap)
		}
		if rawList, ok := value.([]any); ok {
			members := extractMembersPayload(rawList, false)
			return h.addMissingMembersTx(ctx, tx, group, wsID, members)
		}
		return &scim.ScimError{Status: 400, ScimType: "invalidSyntax", Detail: "Pathless PATCH add requires an object value"}
	}
	if strings.HasPrefix(lp, "members[") {
		return h.applyMemberSubAttrAdd(ctx, tx, group, wsID, path, value)
	}
	return &scim.ScimError{Status: 400, ScimType: "invalidPath", Detail: "Unsupported PATCH path: " + path}
}

func (h *GroupHandler) applyGroupReplaceTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, path string, value any) error {
	lp := strings.ToLower(path)
	if lp == "members" {
		members := extractMembersPayload(value, false)
		return h.replaceMembersTx(ctx, tx, group, wsID, members)
	}
	if lp == "displayname" {
		s, ok := value.(string)
		s = scim.NormalizeNFC(s)
		if !ok || s == "" {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'displayName' must be a non-empty string"}
		}
		return h.updateDisplayNameTx(ctx, tx, group, wsID, s)
	}
	if lp == "externalid" {
		if value == nil {
			group.ExternalID = nil
			return nil
		}
		s, ok := value.(string)
		if !ok {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'externalId' must be a string"}
		}
		norm := scim.NormalizeNFC(s)
		group.ExternalID = &norm
		return nil
	}
	if path == "" {
		valueMap, ok := value.(map[string]any)
		if !ok {
			return &scim.ScimError{Status: 400, ScimType: "invalidSyntax", Detail: "Pathless PATCH replace requires an object value"}
		}
		return h.applyReplaceValueMapTx(ctx, tx, group, wsID, valueMap)
	}
	if strings.HasPrefix(lp, "members[") {
		if strings.HasSuffix(lp, ".type") || strings.HasSuffix(lp, ".value") || strings.HasSuffix(lp, ".$ref") {
			return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Group member attribute is immutable"}
		}
		if strings.HasSuffix(lp, ".display") {
			return nil
		}
	}
	return &scim.ScimError{Status: 400, ScimType: "invalidPath", Detail: "Unsupported PATCH path: " + path}
}

func (h *GroupHandler) applyGroupRemoveTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, path string, value any) error {
	lp := strings.ToLower(path)
	if lp == "displayname" {
		return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Required attribute 'displayName' cannot be removed"}
	}
	if lp == "externalid" {
		group.ExternalID = nil
		return nil
	}
	if lp == "members" {
		if rawList, ok := value.([]any); ok && len(rawList) > 0 {
			return h.removeMembersByValueListTx(ctx, tx, group, rawList)
		}
		if h.membershipRepo != nil {
			if err := h.membershipRepo.DeleteByGroupIDTx(ctx, tx, group.ID); err != nil {
				return err
			}
		}
		group.Members = nil
		return nil
	}
	if strings.HasPrefix(lp, "members[") {
		closeIdx := strings.IndexByte(path, ']')
		if closeIdx < 8 {
			return &scim.ScimError{Status: 400, ScimType: "invalidFilter", Detail: "Invalid member filter in path: " + path}
		}
		filterExpr := strings.TrimSpace(path[8:closeIdx])
		if filterExpr == "" {
			return &scim.ScimError{Status: 400, ScimType: "invalidFilter", Detail: "Empty valuePath filter in path: " + path}
		}
		rest := strings.ToLower(strings.TrimSpace(path[closeIdx+1:]))
		if rest == ".value" || rest == ".type" || rest == ".$ref" {
			return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Group member attribute is immutable and cannot be removed"}
		}
		targetValue := extractFilterValue(filterExpr)
		if targetValue != "" {
			targetUUID, err := uuid.Parse(targetValue)
			if err == nil {
				if h.membershipRepo != nil {
					if err := h.membershipRepo.DeleteByGroupIDAndMemberValuesTx(ctx, tx, group.ID, []uuid.UUID{targetUUID}); err != nil {
						return err
					}
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
	if path == "" {
		if rawList, ok := value.([]any); ok {
			return h.removeMembersByValueListTx(ctx, tx, group, rawList)
		}
		return &scim.ScimError{Status: 400, ScimType: "noTarget", Detail: "PATCH remove operation requires a 'path'"}
	}
	return &scim.ScimError{Status: 400, ScimType: "invalidPath", Detail: "Unsupported PATCH remove path: " + path}
}

func (h *GroupHandler) removeMembersByValueListTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, rawList []any) error {
	for _, item := range rawList {
		if memberMap, ok := item.(map[string]any); ok {
			if err := checkMemberValueRefConflict(memberMap); err != nil {
				return err
			}
			memberValue := resolveMemberID(memberMap)
			if memberValue != "" {
				memberUUID, err := uuid.Parse(memberValue)
				if err == nil {
					if h.membershipRepo != nil {
						if err := h.membershipRepo.DeleteByGroupIDAndMemberValuesTx(ctx, tx, group.ID, []uuid.UUID{memberUUID}); err != nil {
							slog.Error("failed to remove member", "error", err)
						}
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
	return nil
}

func (h *GroupHandler) applyAddValueMapTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, valueMap map[string]any) error {
	for rawKey, v := range valueMap {
		if strings.EqualFold(rawKey, "schemas") {
			continue
		}
		cleanKey := cleanGroupPatchPath(rawKey)
		if isGroupReadOnlyAttr(cleanKey) {
			return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Attribute '" + cleanKey + "' is readOnly and cannot be modified"}
		}
		switch strings.ToLower(cleanKey) {
		case "displayname":
			s, ok := v.(string)
			s = scim.NormalizeNFC(s)
			if !ok || s == "" {
				return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'displayName' must be a non-empty string"}
			}
			if err := h.updateDisplayNameTx(ctx, tx, group, wsID, s); err != nil {
				return err
			}
		case "externalid":
			if v == nil {
				continue
			}
			s, ok := v.(string)
			if !ok {
				return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'externalId' must be a string"}
			}
			norm := scim.NormalizeNFC(s)
			group.ExternalID = &norm
		case "members":
			members := extractMembersPayload(v, false)
			if err := h.addMissingMembersTx(ctx, tx, group, wsID, members); err != nil {
				return err
			}
		default:
			return &scim.ScimError{Status: 400, ScimType: "invalidPath", Detail: "Unknown Group attribute: " + cleanKey}
		}
	}
	return nil
}

func (h *GroupHandler) applyReplaceValueMapTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, valueMap map[string]any) error {
	for rawKey, v := range valueMap {
		if strings.EqualFold(rawKey, "schemas") {
			continue
		}
		cleanKey := cleanGroupPatchPath(rawKey)
		if isGroupReadOnlyAttr(cleanKey) {
			return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Attribute '" + cleanKey + "' is readOnly and cannot be modified"}
		}
		switch strings.ToLower(cleanKey) {
		case "displayname":
			s, ok := v.(string)
			s = scim.NormalizeNFC(s)
			if !ok || s == "" {
				return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'displayName' must be a non-empty string"}
			}
			if err := h.updateDisplayNameTx(ctx, tx, group, wsID, s); err != nil {
				return err
			}
		case "externalid":
			if v == nil {
				group.ExternalID = nil
			} else {
				s, ok := v.(string)
				if !ok {
					return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Attribute 'externalId' must be a string"}
				}
				norm := scim.NormalizeNFC(s)
				group.ExternalID = &norm
			}
		case "members":
			members := extractMembersPayload(v, false)
			if err := h.replaceMembersTx(ctx, tx, group, wsID, members); err != nil {
				return err
			}
		default:
			return &scim.ScimError{Status: 400, ScimType: "invalidPath", Detail: "Unknown Group attribute: " + cleanKey}
		}
	}
	return nil
}

func (h *GroupHandler) updateDisplayNameTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, newName string) error {
	newName = scim.NormalizeNFC(newName)
	if group.DisplayName != newName {
		existing, err := h.groupRepo.FindByDisplayNameAndWorkspaceIDTx(ctx, tx, newName, wsID)
		if err != nil {
			return err
		}
		if existing != nil && existing.ID != group.ID {
			return &scim.ScimError{Status: 409, ScimType: "uniqueness",
				Detail: "Group with displayName '" + newName + "' already exists"}
		}
	}
	group.DisplayName = newName
	return nil
}

func (h *GroupHandler) addMissingMembersTx(ctx context.Context, tx jdbc.Executor, group *model.ScimGroup, wsID uuid.UUID, members []map[string]any) error {
	addedAny := false
	newlyAdded := make(map[string]bool)
	existingMembers := make(map[string]bool, len(group.Members))
	for _, existing := range group.Members {
		existingMembers[existing.MemberValue.String()] = true
	}

	for _, member := range members {
		if err := checkMemberValueRefConflict(member); err != nil {
			return err
		}
		memberValue := resolveMemberID(member)
		if memberValue == "" {
			if refStr, ok := member["$ref"].(string); ok && strings.TrimSpace(refStr) != "" {
				return h.addMemberTx(ctx, tx, group.ID, wsID, member)
			}
			continue
		}

		memberKey := memberValue
		if memberUUID, err := uuid.Parse(memberValue); err == nil {
			memberKey = memberUUID.String()
		}

		if existingMembers[memberKey] || newlyAdded[memberKey] {
			continue
		}
		if err := h.addMemberTx(ctx, tx, group.ID, wsID, member); err != nil {
			return err
		}
		newlyAdded[memberKey] = true
		addedAny = true
	}

	if addedAny {
		memberships, err := h.membershipRepo.FindByGroupIDTx(ctx, tx, group.ID)
		if err != nil {
			return err
		}
		group.Members = memberships
	}
	return nil
}

func (h *GroupHandler) touchWorkspace(ctx context.Context, wsID uuid.UUID) {
	if h.workspaceRepo == nil {
		return
	}
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
	if matches := memberValueFilterRe.FindStringSubmatch(filterExpr); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	if matches := memberRefFilterRe.FindStringSubmatch(filterExpr); len(matches) > 1 {
		return scim.ExtractUUIDFromRef(matches[1])
	}
	return ""
}

// applyMemberSubAttrAdd enforces RFC 7644 §3.5.2 on Group.members immutable sub-attributes:
//   - .value and .$ref always have a value on existing members -> 400 mutability.
//   - .type MAY be added if the member previously had no type set (nil or ""), whereas
//     adding a different type when one is already set returns 400 mutability.
func (h *GroupHandler) applyMemberSubAttrAdd(
	ctx context.Context,
	tx jdbc.Executor,
	group *model.ScimGroup,
	wsID uuid.UUID,
	path string,
	value any,
) error {
	closeIdx := strings.IndexByte(path, ']')
	if closeIdx < 8 {
		return &scim.ScimError{Status: 400, ScimType: "invalidFilter", Detail: "Invalid member filter in path: " + path}
	}
	filterExpr := strings.TrimSpace(path[8:closeIdx])
	if filterExpr == "" {
		return &scim.ScimError{Status: 400, ScimType: "invalidFilter", Detail: "Empty valuePath filter in path: " + path}
	}
	rest := strings.ToLower(strings.TrimSpace(path[closeIdx+1:]))
	if rest == ".value" || rest == ".$ref" {
		return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Group member attribute is immutable"}
	}
	if rest == ".display" {
		return nil
	}
	if rest != ".type" {
		return &scim.ScimError{Status: 400, ScimType: "invalidPath", Detail: "Unsupported PATCH path: " + path}
	}

	rawType, ok := value.(string)
	if !ok || strings.TrimSpace(rawType) == "" {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Member type must be 'User' or 'Group'"}
	}
	var canonicalType string
	switch {
	case strings.EqualFold(strings.TrimSpace(rawType), "User"):
		canonicalType = "User"
	case strings.EqualFold(strings.TrimSpace(rawType), "Group"):
		canonicalType = "Group"
	default:
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Invalid member type: " + rawType}
	}

	targetValue := extractFilterValue(filterExpr)
	targetUUID, err := uuid.Parse(targetValue)
	if targetValue == "" || err != nil {
		return &scim.ScimError{Status: 400, ScimType: "noTarget", Detail: "No matching member found for path: " + path}
	}

	matchIdx := -1
	for i := range group.Members {
		if group.Members[i].MemberValue == targetUUID {
			matchIdx = i
			break
		}
	}
	if matchIdx < 0 {
		return &scim.ScimError{Status: 400, ScimType: "noTarget", Detail: "No matching member found for path: " + path}
	}

	existing := group.Members[matchIdx].MemberType
	if existing != nil && strings.TrimSpace(*existing) != "" {
		if !strings.EqualFold(strings.TrimSpace(*existing), canonicalType) {
			return &scim.ScimError{Status: 400, ScimType: "mutability", Detail: "Group member attribute is immutable"}
		}
		return nil
	}

	// Verify target resource exists with matching type when repositories are wired.
	if canonicalType == "User" && h.userRepo != nil {
		var u *model.ScimUser
		var uErr error
		if tx != nil {
			u, uErr = h.userRepo.FindByIDAndWorkspaceIDTx(ctx, tx, targetUUID, wsID)
		} else {
			u, uErr = h.userRepo.FindByIDAndWorkspaceID(ctx, targetUUID, wsID)
		}
		if uErr != nil || u == nil {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Referenced User member not found: " + targetUUID.String()}
		}
	} else if canonicalType == "Group" && h.groupRepo != nil {
		var g *model.ScimGroup
		var gErr error
		if tx != nil {
			g, gErr = h.groupRepo.FindByIDAndWorkspaceIDTx(ctx, tx, targetUUID, wsID)
		} else {
			g, gErr = h.groupRepo.FindByIDAndWorkspaceID(ctx, targetUUID, wsID)
		}
		if gErr != nil || g == nil {
			return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "Referenced Group member not found: " + targetUUID.String()}
		}
	}

	if h.membershipRepo != nil && group.Members[matchIdx].ID != uuid.Nil {
		if tx != nil {
			if err := h.membershipRepo.UpdateMemberTypeTx(ctx, tx, group.Members[matchIdx].ID, wsID, canonicalType); err != nil {
				return err
			}
		} else {
			if err := h.membershipRepo.UpdateMemberType(ctx, group.Members[matchIdx].ID, wsID, canonicalType); err != nil {
				return err
			}
		}
	}
	group.Members[matchIdx].MemberType = &canonicalType
	return nil
}
