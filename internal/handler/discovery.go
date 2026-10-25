package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

type DiscoveryHandler struct {
	userHandler  *UserHandler
	groupHandler *GroupHandler
}

func NewDiscoveryHandler(handlers ...any) *DiscoveryHandler {
	dh := &DiscoveryHandler{}
	for _, h := range handlers {
		switch v := h.(type) {
		case *UserHandler:
			dh.userHandler = v
		case *GroupHandler:
			dh.groupHandler = v
		}
	}
	return dh
}

func (h *DiscoveryHandler) SetHandlers(userHandler *UserHandler, groupHandler *GroupHandler) {
	h.userHandler = userHandler
	h.groupHandler = groupHandler
}

func (h *DiscoveryHandler) GetServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, scim.ServiceProviderConfig())
}

func (h *DiscoveryHandler) GetSchemas(w http.ResponseWriter, r *http.Request) {
	schemas := scim.AllSchemas()
	response := map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(schemas),
		"startIndex":   1,
		"itemsPerPage": len(schemas),
		"Resources":    schemas,
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *DiscoveryHandler) GetSchemaByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if decoded, err := url.PathUnescape(id); err == nil {
		id = decoded
	}
	schema := scim.GetSchemaByID(id)
	if schema == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Schema not found: "+id))
		return
	}
	writeJSON(w, http.StatusOK, schema)
}

func (h *DiscoveryHandler) GetResourceTypes(w http.ResponseWriter, r *http.Request) {
	baseURL := buildBaseURL(r)
	rts := scim.ResourceTypes(baseURL)
	response := map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(rts),
		"startIndex":   1,
		"itemsPerPage": len(rts),
		"Resources":    rts,
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *DiscoveryHandler) GetResourceTypeByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if decoded, err := url.PathUnescape(id); err == nil {
		id = decoded
	}
	baseURL := buildBaseURL(r)
	rt := scim.GetResourceTypeByID(id, baseURL)
	if rt == nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "ResourceType not found: "+id))
		return
	}
	writeJSON(w, http.StatusOK, rt)
}

func (h *DiscoveryHandler) GlobalSearchNotImplemented(w http.ResponseWriter, _ *http.Request) {
	scim.WriteScimError(w, scim.NewScimError(http.StatusNotImplemented, "", "Global cross-resource search is not implemented"))
}

func MethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	scim.WriteScimError(w, scim.NewScimError(http.StatusMethodNotAllowed, "", "Method not allowed"))
}

// RootSearch implements root-level querying for GET / and POST /.search (RFC 7644 §3.4.2 & §3.4.3).
func (h *DiscoveryHandler) RootSearch(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	filterStr := r.URL.Query().Get("filter")
	startIndex := clampInt(r.URL.Query().Get("startIndex"), 1, 1)
	count := clampIntMax(r.URL.Query().Get("count"), 100, 0, 200)
	sortBy := r.URL.Query().Get("sortBy")
	sortOrder := r.URL.Query().Get("sortOrder")
	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")

	if r.Method == http.MethodPost {
		var body map[string]any
		if err := readJSON(r, &body); err != nil {
			if err != io.EOF {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
				return
			}
		} else if body != nil {
			if f, ok := body["filter"].(string); ok {
				filterStr = f
			}
			if si, ok := body["startIndex"].(float64); ok {
				startIndex = max(1, int(si))
			}
			if c, ok := body["count"].(float64); ok {
				count = max(0, min(200, int(c)))
			}
			if sb, ok := body["sortBy"].(string); ok {
				sortBy = sb
			}
			if so, ok := body["sortOrder"].(string); ok {
				sortOrder = so
			}
			if a, ok := body["attributes"].([]any); ok {
				strs := make([]string, 0, len(a))
				for _, v := range a {
					if s, ok := v.(string); ok {
						strs = append(strs, s)
					}
				}
				attrs = strings.Join(strs, ",")
			}
			if ea, ok := body["excludedAttributes"].([]any); ok {
				strs := make([]string, 0, len(ea))
				for _, v := range ea {
					if s, ok := v.(string); ok {
						strs = append(strs, s)
					}
				}
				excludedAttrs = strings.Join(strs, ",")
			}
		}
	}

	hasUser := (h.userHandler != nil)
	hasGroup := (h.groupHandler != nil)

	var userFilterResult *scim.FilterResult
	var groupFilterResult *scim.FilterResult

	if filterStr != "" {
		lower := strings.ToLower(filterStr)
		if strings.Contains(lower, "meta.resourcetype") {
			isUserScoped := (strings.Contains(lower, `eq "user"`) || strings.Contains(lower, `eq 'user'`)) && !strings.Contains(lower, "group")
			isGroupScoped := (strings.Contains(lower, `eq "group"`) || strings.Contains(lower, `eq 'group'`)) && !strings.Contains(lower, "user")
			if isUserScoped {
				hasGroup = false
			} else if isGroupScoped {
				hasUser = false
			}
		}

		var userErr, groupErr error
		if hasUser {
			userFilterResult, userErr = scim.ParseUserFilter(filterStr, 2)
		}
		if hasGroup {
			groupFilterResult, groupErr = scim.ParseGroupFilter(filterStr, 2)
		}

		if hasUser && userErr != nil {
			if strings.Contains(strings.ToLower(userErr.Error()), "unknown attribute") {
				hasUser = false
				userFilterResult = nil
			}
		}
		if hasGroup && groupErr != nil {
			if strings.Contains(strings.ToLower(groupErr.Error()), "unknown attribute") {
				hasGroup = false
				groupFilterResult = nil
			}
		}

		if !hasUser && !hasGroup {
			errToReport := userErr
			if errToReport == nil {
				errToReport = groupErr
			}
			errMsg := "Invalid filter"
			if errToReport != nil {
				errMsg += ": " + errToReport.Error()
			}
			scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidFilter", errMsg))
			return
		}
	}

	baseURL := buildBaseURL(r)
	compat := getCompatMode(r)

	var resources []map[string]any
	totalResults := 0

	if hasUser && !hasGroup {
		tot, userRes, err := h.queryUsers(r.Context(), wsID, userFilterResult, sortBy, sortOrder, max(0, startIndex-1), count, baseURL, compat, attrs, excludedAttrs)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
		totalResults = tot
		resources = userRes
	} else if !hasUser && hasGroup {
		tot, groupRes, err := h.queryGroups(r.Context(), wsID, groupFilterResult, sortBy, sortOrder, max(0, startIndex-1), count, baseURL, attrs, excludedAttrs)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
		totalResults = tot
		resources = groupRes
	} else if hasUser && hasGroup {
		totUsers, _, err := h.queryUsers(r.Context(), wsID, userFilterResult, "", "", 0, 0, baseURL, compat, attrs, excludedAttrs)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
		totGroups, _, err := h.queryGroups(r.Context(), wsID, groupFilterResult, "", "", 0, 0, baseURL, attrs, excludedAttrs)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
		totalResults = totUsers + totGroups

		if count > 0 {
			if sortBy != "" {
				fetchLimit := startIndex - 1 + count
				if fetchLimit > 200 {
					fetchLimit = 200
				}
				_, uRes, _ := h.queryUsers(r.Context(), wsID, userFilterResult, sortBy, sortOrder, 0, fetchLimit, baseURL, compat, attrs, excludedAttrs)
				_, gRes, _ := h.queryGroups(r.Context(), wsID, groupFilterResult, sortBy, sortOrder, 0, fetchLimit, baseURL, attrs, excludedAttrs)
				combined := append(uRes, gRes...)
				sortResources(combined, sortBy, sortOrder)

				offset := startIndex - 1
				if offset < len(combined) {
					end := offset + count
					if end > len(combined) {
						end = len(combined)
					}
					resources = combined[offset:end]
				} else {
					resources = []map[string]any{}
				}
			} else {
				offset := startIndex - 1
				if offset < totUsers {
					uCount := min(count, totUsers-offset)
					_, uRes, _ := h.queryUsers(r.Context(), wsID, userFilterResult, "", "", offset, uCount, baseURL, compat, attrs, excludedAttrs)
					resources = append(resources, uRes...)
					if len(resources) < count {
						gNeeded := count - len(resources)
						_, gRes, _ := h.queryGroups(r.Context(), wsID, groupFilterResult, "", "", 0, gNeeded, baseURL, attrs, excludedAttrs)
						resources = append(resources, gRes...)
					}
				} else {
					gOffset := offset - totUsers
					_, gRes, _ := h.queryGroups(r.Context(), wsID, groupFilterResult, "", "", gOffset, count, baseURL, attrs, excludedAttrs)
					resources = gRes
				}
			}
		}
	}

	if resources == nil {
		resources = []map[string]any{}
	}

	listResponse := map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": totalResults,
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}

	writeJSON(w, http.StatusOK, listResponse)
}

func (h *DiscoveryHandler) queryUsers(
	ctx context.Context,
	wsID uuid.UUID,
	filterResult *scim.FilterResult,
	sortBy, sortOrder string,
	offset, count int,
	baseURL string,
	compat scim.CompatMode,
	attrs, excludedAttrs string,
) (int, []map[string]any, error) {
	if h.userHandler == nil {
		return 0, nil, nil
	}

	sortColumn := ""
	if sortBy != "" {
		sortColumn = scim.ResolveUserSortAttribute(sortBy)
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

	totalCount64, err := h.userHandler.userRepo.Count(ctx, wsID, whereClause, filterArgs)
	if err != nil {
		return 0, nil, err
	}
	totalCount := int(totalCount64)

	if count == 0 {
		return totalCount, []map[string]any{}, nil
	}

	users, err := h.userHandler.userRepo.List(ctx, wsID, whereClause, filterArgs, sortColumn, sortDir, offset, count)
	if err != nil {
		return 0, nil, err
	}

	groupsMap := h.userHandler.getUserGroupsBatch(ctx, users, baseURL)

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

	return totalCount, resources, nil
}

func (h *DiscoveryHandler) queryGroups(
	ctx context.Context,
	wsID uuid.UUID,
	filterResult *scim.FilterResult,
	sortBy, sortOrder string,
	offset, count int,
	baseURL string,
	attrs, excludedAttrs string,
) (int, []map[string]any, error) {
	if h.groupHandler == nil {
		return 0, nil, nil
	}

	sortColumn := "display_name"
	if sortBy != "" {
		if col := scim.ResolveGroupSortAttribute(sortBy); col != "" {
			sortColumn = col
		}
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

	totalCount64, err := h.groupHandler.groupRepo.Count(ctx, wsID, whereClause, filterArgs)
	if err != nil {
		return 0, nil, err
	}
	totalCount := int(totalCount64)

	if count == 0 {
		return totalCount, []map[string]any{}, nil
	}

	groups, err := h.groupHandler.groupRepo.List(ctx, wsID, whereClause, filterArgs, sortColumn, sortDir, offset, count)
	if err != nil {
		return 0, nil, err
	}

	for _, g := range groups {
		memberships, _ := h.groupHandler.membershipRepo.FindByGroupID(ctx, g.ID)
		g.Members = memberships
	}

	resources := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		response := scim.GroupToScimResponse(g, baseURL)
		response = applyAttributeProjection(response, attrs, excludedAttrs)
		resources = append(resources, response)
	}

	return totalCount, resources, nil
}

func sortResources(items []map[string]any, sortBy, sortOrder string) {
	if len(items) <= 1 || sortBy == "" {
		return
	}
	isDesc := strings.EqualFold(sortOrder, "descending")
	sort.SliceStable(items, func(i, j int) bool {
		valI, okI := extractSortAttr(items[i], sortBy)
		valJ, okJ := extractSortAttr(items[j], sortBy)
		if !okI && !okJ {
			return false
		}
		if isDesc {
			if !okI {
				return true
			}
			if !okJ {
				return false
			}
			return strings.ToLower(valI) > strings.ToLower(valJ)
		}
		if !okI {
			return false
		}
		if !okJ {
			return true
		}
		return strings.ToLower(valI) < strings.ToLower(valJ)
	})
}

func extractSortAttr(res map[string]any, sortBy string) (string, bool) {
	if res == nil {
		return "", false
	}
	parts := strings.Split(sortBy, ".")
	var current any = res
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		var found any
		foundOk := false
		for k, v := range m {
			if strings.EqualFold(k, part) {
				found = v
				foundOk = true
				break
			}
		}
		if !foundOk || found == nil {
			return "", false
		}
		current = found
	}
	switch v := current.(type) {
	case string:
		return v, true
	default:
		return fmt.Sprintf("%v", v), true
	}
}
