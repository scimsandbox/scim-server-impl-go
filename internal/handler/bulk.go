package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

const (
	bulkRequestSchema   = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	userCollectionPath  = "/Users/"
	groupCollectionPath = "/Groups/"
	userNotFoundDetail  = "User not found"
	groupNotFoundDetail = "Group not found"
	maxOperations       = 1000
	maxPayloadSize      = 1048576 // 1 MB
)

type BulkHandler struct {
	userHandler  *UserHandler
	groupHandler *GroupHandler
}

func NewBulkHandler(userHandler *UserHandler, groupHandler *GroupHandler) *BulkHandler {
	return &BulkHandler{
		userHandler:  userHandler,
		groupHandler: groupHandler,
	}
}

func (h *BulkHandler) ProcessBulk(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
		return
	}

	// Validate content length
	if r.ContentLength > maxPayloadSize {
		scim.WriteScimError(w, scim.NewScimError(http.StatusRequestEntityTooLarge, "",
			fmt.Sprintf("Bulk request exceeds maxPayloadSize (%d bytes)", maxPayloadSize)))
		return
	}

	// Validate schema
	schemas, _ := body["schemas"].([]any)
	validSchema := false
	for _, s := range schemas {
		if s == bulkRequestSchema {
			validSchema = true
			break
		}
	}
	if !validSchema {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue",
			"Bulk request must include BulkRequest schema"))
		return
	}

	rawOps, _ := body["Operations"].([]any)
	if rawOps == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidValue",
			"Bulk request must contain Operations"))
		return
	}
	if len(rawOps) > maxOperations {
		scim.WriteScimError(w, scim.NewScimError(http.StatusRequestEntityTooLarge, "",
			fmt.Sprintf("Bulk request exceeds maxOperations (%d)", maxOperations)))
		return
	}

	failOnErrors := 0
	if v, ok := body["failOnErrors"]; ok {
		if n, ok := v.(float64); ok {
			failOnErrors = int(n)
		}
	}

	bulkIdMap := make(map[string]string)
	results := make([]map[string]any, 0, len(rawOps))
	errorCount := 0

	for _, rawOp := range rawOps {
		op, ok := rawOp.(map[string]any)
		if !ok {
			continue
		}

		result := h.processOperation(r, op, wsID, bulkIdMap)
		results = append(results, result)

		if isErrorResult(result) {
			errorCount++
			if failOnErrors > 0 && errorCount >= failOnErrors {
				break
			}
		}
	}

	response := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"},
		"Operations": results,
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *BulkHandler) processOperation(r *http.Request, op map[string]any, wsID uuid.UUID, bulkIdMap map[string]string) map[string]any {
	rawMethod, _ := op["method"].(string)
	method := strings.ToUpper(rawMethod)
	path, _ := op["path"].(string)
	bulkId, _ := op["bulkId"].(string)
	data, _ := op["data"].(map[string]any)

	result := make(map[string]any)
	if bulkId != "" {
		result["bulkId"] = bulkId
	}
	result["method"] = method

	defer func() {
		if rv := recover(); rv != nil {
			slog.Error("panic in bulk operation", "method", method, "path", path, "error", rv)
			result["status"] = "500"
			result["response"] = buildBulkError("500", "", "Internal server error")
		}
	}()

	// Resolve bulkId references
	if path != "" {
		path = resolveBulkIdReferences(path, bulkIdMap)
	}
	if data != nil {
		data = resolveBulkIdInData(data, bulkIdMap)
	}

	baseURL := buildBaseURL(r)

	switch method {
	case "POST":
		h.handleBulkPost(r, result, path, data, wsID, baseURL, bulkId, bulkIdMap)
	case "PUT":
		h.handleBulkPut(r, result, path, data, wsID, baseURL)
	case "PATCH":
		h.handleBulkPatch(r, result, path, data, wsID, baseURL)
	case "DELETE":
		h.handleBulkDelete(r, result, path, wsID)
	default:
		result["status"] = "400"
		result["response"] = buildBulkError("400", "invalidValue", "Unsupported method: "+method)
	}

	return result
}

func (h *BulkHandler) handleBulkPost(r *http.Request, result map[string]any, path string, data map[string]any, wsID uuid.UUID, baseURL string, bulkId string, bulkIdMap map[string]string) {
	if strings.HasPrefix(path, "/Users") {
		user, err := h.createUserInternal(r, wsID, data)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "201"
		result["location"] = baseURL + userCollectionPath + user.String()
		if bulkId != "" {
			bulkIdMap[bulkId] = user.String()
		}
	} else if strings.HasPrefix(path, "/Groups") {
		group, err := h.createGroupInternal(r, wsID, data)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "201"
		result["location"] = baseURL + groupCollectionPath + group.String()
		if bulkId != "" {
			bulkIdMap[bulkId] = group.String()
		}
	} else {
		result["status"] = "400"
		result["response"] = buildBulkError("400", "invalidValue", "Unknown resource path: "+path)
	}
}

func (h *BulkHandler) handleBulkPut(r *http.Request, result map[string]any, path string, data map[string]any, wsID uuid.UUID, baseURL string) {
	resourceType, resourceID, err := parseBulkPath(path)
	if err != nil {
		setBulkError(result, err)
		return
	}

	switch resourceType {
	case "Users":
		err := h.replaceUserInternal(r, wsID, resourceID, data)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + userCollectionPath + resourceID.String()
	case "Groups":
		err := h.replaceGroupInternal(r, wsID, resourceID, data)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + groupCollectionPath + resourceID.String()
	}
}

func (h *BulkHandler) handleBulkPatch(r *http.Request, result map[string]any, path string, data map[string]any, wsID uuid.UUID, baseURL string) {
	resourceType, resourceID, err := parseBulkPath(path)
	if err != nil {
		setBulkError(result, err)
		return
	}

	ops, _ := data["Operations"].([]any)
	operations := make([]map[string]any, 0, len(ops))
	for _, o := range ops {
		if m, ok := o.(map[string]any); ok {
			operations = append(operations, m)
		}
	}

	switch resourceType {
	case "Users":
		err := h.patchUserInternal(r, wsID, resourceID, operations)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + userCollectionPath + resourceID.String()
	case "Groups":
		err := h.patchGroupInternal(r, wsID, resourceID, operations)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "200"
		result["location"] = baseURL + groupCollectionPath + resourceID.String()
	}
}

func (h *BulkHandler) handleBulkDelete(r *http.Request, result map[string]any, path string, wsID uuid.UUID) {
	resourceType, resourceID, err := parseBulkPath(path)
	if err != nil {
		setBulkError(result, err)
		return
	}

	switch resourceType {
	case "Users":
		err := h.deleteUserInternal(r, wsID, resourceID)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "204"
	case "Groups":
		err := h.deleteGroupInternal(r, wsID, resourceID)
		if err != nil {
			setBulkError(result, err)
			return
		}
		result["status"] = "204"
	}
}

// Internal helpers that wrap handler operations and return errors instead of writing to response

func (h *BulkHandler) createUserInternal(r *http.Request, wsID uuid.UUID, data map[string]any) (*uuid.UUID, error) {
	userName, _ := data["userName"].(string)
	if userName == "" {
		return nil, &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "userName is required"}
	}

	exists, err := h.userHandler.userRepo.ExistsByUserNameAndWorkspaceID(r.Context(), userName, wsID)
	if err != nil {
		return nil, &scim.ScimError{Status: 500, Detail: "Internal error"}
	}
	if exists {
		return nil, &scim.ScimError{Status: 409, ScimType: "uniqueness",
			Detail: "User with userName '" + userName + "' already exists"}
	}

	user := &model.ScimUser{
		ID:           uuid.New(),
		WorkspaceID:  wsID,
		Active:       true,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
		Version:      0,
	}
	scim.ApplyFromScimInput(user, data)

	if err := h.userHandler.userRepo.Create(r.Context(), user); err != nil {
		return nil, &scim.ScimError{Status: 500, Detail: "Failed to create user"}
	}

	h.userHandler.touchWorkspace(r.Context(), wsID)
	return &user.ID, nil
}

func (h *BulkHandler) createGroupInternal(r *http.Request, wsID uuid.UUID, data map[string]any) (*uuid.UUID, error) {
	displayName, _ := data["displayName"].(string)
	if displayName == "" {
		return nil, &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "displayName is required"}
	}

	existing, err := h.groupHandler.groupRepo.FindByDisplayNameAndWorkspaceID(r.Context(), displayName, wsID)
	if err != nil {
		return nil, &scim.ScimError{Status: 500, Detail: "Internal error"}
	}
	if existing != nil {
		return nil, &scim.ScimError{Status: 409, ScimType: "uniqueness",
			Detail: "Group with displayName '" + displayName + "' already exists"}
	}

	group := &model.ScimGroup{
		ID:           uuid.New(),
		WorkspaceID:  wsID,
		DisplayName:  displayName,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
		Version:      0,
	}
	if extID, ok := data["externalId"].(string); ok {
		group.ExternalID = &extID
	}

	if err := h.groupHandler.groupRepo.Create(r.Context(), group); err != nil {
		return nil, &scim.ScimError{Status: 500, Detail: "Failed to create group"}
	}

	// Add members
	if members, ok := data["members"].([]any); ok {
		for _, m := range members {
			if memberMap, ok := m.(map[string]any); ok {
				if err := h.groupHandler.addMember(r.Context(), group.ID, wsID, memberMap); err != nil {
					return nil, err
				}
			}
		}
	}

	h.groupHandler.touchWorkspace(r.Context(), wsID)
	return &group.ID, nil
}

func (h *BulkHandler) replaceUserInternal(r *http.Request, wsID, userID uuid.UUID, data map[string]any) error {
	user, err := h.userHandler.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		return &scim.ScimError{Status: 404, Detail: userNotFoundDetail}
	}

	scim.ClearMutableAttributes(user)
	scim.ApplyFromScimInput(user, data)
	user.LastModified = time.Now()

	if err := h.userHandler.userRepo.Update(r.Context(), user); err != nil {
		return &scim.ScimError{Status: 500, Detail: "Failed to update user"}
	}

	h.userHandler.touchWorkspace(r.Context(), wsID)
	return nil
}

func (h *BulkHandler) replaceGroupInternal(r *http.Request, wsID, groupID uuid.UUID, data map[string]any) error {
	group, err := h.groupHandler.groupRepo.FindByIDAndWorkspaceID(r.Context(), groupID, wsID)
	if err != nil || group == nil {
		return &scim.ScimError{Status: 404, Detail: groupNotFoundDetail}
	}

	displayName, _ := data["displayName"].(string)
	if displayName == "" {
		return &scim.ScimError{Status: 400, ScimType: "invalidValue", Detail: "displayName is required"}
	}

	group.DisplayName = displayName
	if extID, ok := data["externalId"]; ok {
		if s, ok := extID.(string); ok {
			group.ExternalID = &s
		} else {
			group.ExternalID = nil
		}
	} else {
		group.ExternalID = nil
	}

	// Clear and re-add members
	_ = h.groupHandler.membershipRepo.DeleteByGroupID(r.Context(), group.ID)
	if members, ok := data["members"].([]any); ok {
		for _, m := range members {
			if memberMap, ok := m.(map[string]any); ok {
				if err := h.groupHandler.addMember(r.Context(), group.ID, wsID, memberMap); err != nil {
					return err
				}
			}
		}
	}

	group.LastModified = time.Now()
	if err := h.groupHandler.groupRepo.Update(r.Context(), group); err != nil {
		return &scim.ScimError{Status: 500, Detail: "Failed to update group"}
	}

	h.groupHandler.touchWorkspace(r.Context(), wsID)
	return nil
}

func (h *BulkHandler) patchUserInternal(r *http.Request, wsID, userID uuid.UUID, operations []map[string]any) error {
	user, err := h.userHandler.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		return &scim.ScimError{Status: 404, Detail: userNotFoundDetail}
	}

	if err := scim.ApplyPatchOperations(user, operations); err != nil {
		return err
	}

	user.LastModified = time.Now()
	if err := h.userHandler.userRepo.Update(r.Context(), user); err != nil {
		return &scim.ScimError{Status: 500, Detail: "Failed to update user"}
	}

	h.userHandler.touchWorkspace(r.Context(), wsID)
	return nil
}

func (h *BulkHandler) patchGroupInternal(r *http.Request, wsID, groupID uuid.UUID, operations []map[string]any) error {
	group, err := h.groupHandler.groupRepo.FindByIDAndWorkspaceID(r.Context(), groupID, wsID)
	if err != nil || group == nil {
		return &scim.ScimError{Status: 404, Detail: groupNotFoundDetail}
	}

	memberships, _ := h.groupHandler.membershipRepo.FindByGroupID(r.Context(), group.ID)
	group.Members = memberships

	for _, op := range operations {
		if err := h.groupHandler.applyGroupPatchOp(r.Context(), group, wsID, op); err != nil {
			return err
		}
	}

	group.LastModified = time.Now()
	if err := h.groupHandler.groupRepo.Update(r.Context(), group); err != nil {
		return &scim.ScimError{Status: 500, Detail: "Failed to update group"}
	}

	h.groupHandler.touchWorkspace(r.Context(), wsID)
	return nil
}

func (h *BulkHandler) deleteUserInternal(r *http.Request, wsID, userID uuid.UUID) error {
	user, err := h.userHandler.userRepo.FindByIDAndWorkspaceID(r.Context(), userID, wsID)
	if err != nil || user == nil {
		return &scim.ScimError{Status: 404, Detail: userNotFoundDetail}
	}

	_ = h.userHandler.membershipRepo.DeleteByMemberValue(r.Context(), userID)
	if err := h.userHandler.userRepo.Delete(r.Context(), userID, wsID); err != nil {
		return &scim.ScimError{Status: 500, Detail: "Failed to delete user"}
	}

	h.userHandler.touchWorkspace(r.Context(), wsID)
	return nil
}

func (h *BulkHandler) deleteGroupInternal(r *http.Request, wsID, groupID uuid.UUID) error {
	group, err := h.groupHandler.groupRepo.FindByIDAndWorkspaceID(r.Context(), groupID, wsID)
	if err != nil || group == nil {
		return &scim.ScimError{Status: 404, Detail: groupNotFoundDetail}
	}

	_ = h.groupHandler.membershipRepo.DeleteByMemberValue(r.Context(), groupID)
	_ = h.groupHandler.membershipRepo.DeleteByGroupID(r.Context(), groupID)
	if err := h.groupHandler.groupRepo.Delete(r.Context(), groupID, wsID); err != nil {
		return &scim.ScimError{Status: 500, Detail: "Failed to delete group"}
	}

	h.groupHandler.touchWorkspace(r.Context(), wsID)
	return nil
}

// Helpers

func parseBulkPath(path string) (string, uuid.UUID, error) {
	cleaned := strings.TrimPrefix(path, "/")
	parts := strings.SplitN(cleaned, "/", 2)
	if len(parts) < 2 {
		return "", uuid.Nil, &scim.ScimError{Status: 400, ScimType: "invalidPath",
			Detail: "Bulk path must include resource ID: " + path}
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return "", uuid.Nil, &scim.ScimError{Status: 400, ScimType: "invalidValue",
			Detail: "Invalid resource ID: " + parts[1]}
	}
	return parts[0], id, nil
}

func resolveBulkIdReferences(path string, bulkIdMap map[string]string) string {
	for k, v := range bulkIdMap {
		path = strings.ReplaceAll(path, "bulkId:"+k, v)
	}
	return path
}

func resolveBulkIdInData(data map[string]any, bulkIdMap map[string]string) map[string]any {
	resolved := make(map[string]any, len(data))
	for k, v := range data {
		resolved[k] = resolveValue(v, bulkIdMap)
	}
	return resolved
}

func resolveValue(value any, bulkIdMap map[string]string) any {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "bulkId:") {
			ref := v[7:]
			if resolved, ok := bulkIdMap[ref]; ok {
				return resolved
			}
		}
		return v
	case map[string]any:
		return resolveBulkIdInData(v, bulkIdMap)
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = resolveValue(item, bulkIdMap)
		}
		return result
	default:
		return value
	}
}

func isErrorResult(result map[string]any) bool {
	status, _ := result["status"].(string)
	if status == "" {
		return false
	}
	if len(status) > 0 && status[0] >= '4' {
		return true
	}
	return false
}

func setBulkError(result map[string]any, err error) {
	var se *scim.ScimError
	if errors.As(err, &se) {
		result["status"] = fmt.Sprintf("%d", se.Status)
		result["response"] = buildBulkError(fmt.Sprintf("%d", se.Status), se.ScimType, se.Detail)
	} else {
		result["status"] = "500"
		result["response"] = buildBulkError("500", "", "Internal server error")
	}
}

func buildBulkError(status, scimType, detail string) map[string]any {
	err := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  status,
	}
	if scimType != "" {
		err["scimType"] = scimType
	}
	if detail != "" {
		err["detail"] = detail
	}
	return err
}
