package handler

import (
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

type DiscoveryHandler struct{}

func NewDiscoveryHandler() *DiscoveryHandler {
	return &DiscoveryHandler{}
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

func MethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	scim.WriteScimError(w, scim.NewScimError(http.StatusMethodNotAllowed, "", "Method not allowed"))
}
