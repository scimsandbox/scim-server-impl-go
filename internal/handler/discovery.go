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

func rejectDiscoveryFilter(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.URL.Query().Get("filter")) != "" {
		scim.WriteScimError(w, scim.NewScimError(http.StatusForbidden, "invalidFilter", "Filtering is not supported on discovery endpoints"))
		return true
	}
	return false
}

func (h *DiscoveryHandler) GetServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if rejectDiscoveryFilter(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, scim.ServiceProviderConfig())
}

func (h *DiscoveryHandler) GetSchemas(w http.ResponseWriter, r *http.Request) {
	if rejectDiscoveryFilter(w, r) {
		return
	}
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
	if rejectDiscoveryFilter(w, r) {
		return
	}
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
	if rejectDiscoveryFilter(w, r) {
		return
	}
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
	if rejectDiscoveryFilter(w, r) {
		return
	}
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

func MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	allow := "GET"
	if r != nil {
		if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.Routes != nil {
			reqPath := r.URL.RawPath
			if reqPath == "" {
				reqPath = r.URL.Path
			}
			if reqPath == "" {
				reqPath = rctx.RoutePath
			}
			if reqPath == "" {
				reqPath = "/"
			}
			if !rctx.Routes.Match(chi.NewRouteContext(), r.Method, reqPath) {
				candidateMethods := []string{
					http.MethodGet,
					http.MethodPost,
					http.MethodPut,
					http.MethodPatch,
					http.MethodDelete,
				}
				var allowed []string
				for _, m := range candidateMethods {
					if rctx.Routes.Match(chi.NewRouteContext(), m, reqPath) {
						allowed = append(allowed, m)
					}
				}
				if len(allowed) > 0 {
					allow = strings.Join(allowed, ", ")
				}
			}
		}
	}
	w.Header().Set("Allow", allow)
	scim.WriteScimError(w, scim.NewScimError(http.StatusMethodNotAllowed, "", "Method not allowed"))
}

func MethodNotAllowedWithAllow(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		scim.WriteScimError(w, scim.NewScimError(http.StatusMethodNotAllowed, "", "Method not allowed"))
	}
}

// RootSearch implements root-level querying for GET / and POST /.search (RFC 7644 §3.4.2 & §3.4.3).
func (h *DiscoveryHandler) RootSearch(w http.ResponseWriter, r *http.Request) {
	wsID, err := resolveWorkspaceID(r)
	if err != nil {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Workspace not found"))
		return
	}

	compatParam := chi.URLParam(r, "compat")
	if compatParam != "" && !strings.EqualFold(compatParam, "ms") {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Resource or endpoint not found: "+compatParam))
		return
	}

	var body map[string]any
	if r.Method == http.MethodPost {
		if err := readJSON(r, &body); err != nil {
			if err != io.EOF {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
				return
			}
		}
	}

	pag, scimErr := parsePagination(r.URL.Query(), body, wsID, 100)
	if scimErr != nil {
		scim.WriteScimError(w, scimErr)
		return
	}

	filterStr := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sortBy")
	sortOrder := r.URL.Query().Get("sortOrder")
	attrs := r.URL.Query().Get("attributes")
	excludedAttrs := r.URL.Query().Get("excludedAttributes")

	if body != nil {
		if f, ok := body["filter"].(string); ok {
			filterStr = f
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

	hasUser := (h.userHandler != nil)
	hasGroup := (h.groupHandler != nil)

	var userFilterResult *scim.FilterResult
	var groupFilterResult *scim.FilterResult

	if filterStr != "" {
		uf, uErr := scim.ParseUserFilterForRoot(filterStr, 2)
		if uErr != nil {
			if scimErr, ok := uErr.(*scim.ScimError); ok {
				scim.WriteScimError(w, scimErr)
			} else {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidFilter", "Invalid filter: "+uErr.Error()))
			}
			return
		}
		gf, gErr := scim.ParseGroupFilterForRoot(filterStr, 2)
		if gErr != nil {
			if scimErr, ok := gErr.(*scim.ScimError); ok {
				scim.WriteScimError(w, scimErr)
			} else {
				scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidFilter", "Invalid filter: "+gErr.Error()))
			}
			return
		}
		userFilterResult = uf
		groupFilterResult = gf
	}

	baseURL := buildBaseURL(r)
	compat := getCompatMode(r)

	var resources []map[string]any
	totalResults := 0

	if hasUser && !hasGroup {
		tot, userRes, err := h.queryUsers(r.Context(), wsID, userFilterResult, sortBy, sortOrder, pag.Offset, pag.Count, baseURL, compat, attrs, excludedAttrs)
		if err != nil {
			scim.WriteScimError(w, scim.NewScimError(http.StatusInternalServerError, "", "Internal error"))
			return
		}
		totalResults = tot
		resources = userRes
	} else if !hasUser && hasGroup {
		tot, groupRes, err := h.queryGroups(r.Context(), wsID, groupFilterResult, sortBy, sortOrder, pag.Offset, pag.Count, baseURL, attrs, excludedAttrs)
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

		if pag.Count > 0 {
			if sortBy != "" {
				fetchLimit := pag.Offset + pag.Count
				if fetchLimit > 200 {
					fetchLimit = 200
				}
				_, uRes, _ := h.queryUsers(r.Context(), wsID, userFilterResult, sortBy, sortOrder, 0, fetchLimit, baseURL, compat, attrs, excludedAttrs)
				_, gRes, _ := h.queryGroups(r.Context(), wsID, groupFilterResult, sortBy, sortOrder, 0, fetchLimit, baseURL, attrs, excludedAttrs)
				combined := append(uRes, gRes...)
				sortResources(combined, sortBy, sortOrder)

				offset := pag.Offset
				if offset < len(combined) {
					end := offset + pag.Count
					if end > len(combined) {
						end = len(combined)
					}
					resources = combined[offset:end]
				} else {
					resources = []map[string]any{}
				}
			} else {
				offset := pag.Offset
				if offset < totUsers {
					uCount := min(pag.Count, totUsers-offset)
					_, uRes, _ := h.queryUsers(r.Context(), wsID, userFilterResult, "", "", offset, uCount, baseURL, compat, attrs, excludedAttrs)
					resources = append(resources, uRes...)
					if len(resources) < pag.Count {
						gNeeded := pag.Count - len(resources)
						_, gRes, _ := h.queryGroups(r.Context(), wsID, groupFilterResult, "", "", 0, gNeeded, baseURL, attrs, excludedAttrs)
						resources = append(resources, gRes...)
					}
				} else {
					gOffset := offset - totUsers
					_, gRes, _ := h.queryGroups(r.Context(), wsID, groupFilterResult, "", "", gOffset, pag.Count, baseURL, attrs, excludedAttrs)
					resources = gRes
				}
			}
		}
	}

	if resources == nil {
		resources = []map[string]any{}
	}

	listResponse := buildListResponse(pag, wsID, totalResults, resources)
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

func isCaseExactSortAttr(sortBy string) bool {
	lower := strings.ToLower(strings.TrimSpace(sortBy))
	entPrefix := strings.ToLower(scim.EnterpriseSchemaURN) + ":"
	userPrefix := strings.ToLower(scim.UserSchemaURN) + ":"
	groupPrefix := strings.ToLower(scim.GroupSchemaURN) + ":"
	if strings.HasPrefix(lower, entPrefix) {
		lower = lower[len(entPrefix):]
	} else if strings.HasPrefix(lower, userPrefix) {
		lower = lower[len(userPrefix):]
	} else if strings.HasPrefix(lower, groupPrefix) {
		lower = lower[len(groupPrefix):]
	}
	switch lower {
	case "id", "externalid", "profileurl", "meta.version", "meta.location", "manager.value", "manager.$ref":
		return true
	}
	return false
}

func sortResources(items []map[string]any, sortBy, sortOrder string) {
	if len(items) <= 1 || sortBy == "" {
		return
	}
	isDesc := strings.EqualFold(sortOrder, "descending")
	caseExact := isCaseExactSortAttr(sortBy)
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
			if caseExact {
				return valI > valJ
			}
			li, lj := strings.ToLower(valI), strings.ToLower(valJ)
			if li != lj {
				return li > lj
			}
			return valI > valJ
		}
		if !okI {
			return false
		}
		if !okJ {
			return true
		}
		if caseExact {
			return valI < valJ
		}
		li, lj := strings.ToLower(valI), strings.ToLower(valJ)
		if li != lj {
			return li < lj
		}
		return valI < valJ
	})
}

func extractSortAttr(res map[string]any, sortBy string) (string, bool) {
	if res == nil {
		return "", false
	}
	var current any = res
	path := strings.TrimSpace(sortBy)
	lower := strings.ToLower(path)
	entPrefix := strings.ToLower(scim.EnterpriseSchemaURN) + ":"
	userPrefix := strings.ToLower(scim.UserSchemaURN) + ":"
	groupPrefix := strings.ToLower(scim.GroupSchemaURN) + ":"
	if strings.HasPrefix(lower, entPrefix) {
		var entMap any
		for k, v := range res {
			if strings.EqualFold(k, scim.EnterpriseSchemaURN) {
				entMap = v
				break
			}
		}
		if entMap == nil {
			return "", false
		}
		current = entMap
		path = path[len(entPrefix):]
	} else if strings.HasPrefix(lower, userPrefix) {
		path = path[len(userPrefix):]
	} else if strings.HasPrefix(lower, groupPrefix) {
		path = path[len(groupPrefix):]
	}

	parts := strings.Split(path, ".")
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
