package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

const ScimContentType = "application/scim+json"

func resolveWorkspaceID(r *http.Request) (uuid.UUID, error) {
	wsID := r.Context().Value(middleware.WorkspaceIDKey)
	if wsID == nil {
		return uuid.Nil, fmt.Errorf("workspace ID not found")
	}
	return wsID.(uuid.UUID), nil
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// buildBaseURL derives the authority stamped into every meta.location and $ref.
//
// Only the scheme comes from a forwarded header: the edge terminates TLS and reaches this service
// over plain http, and it overwrites X-Forwarded-Proto itself. X-Forwarded-Host and X-Forwarded-Port
// are deliberately NOT read - any client can send them, and they would let a caller choose the host
// every URL in the response points at. r.Host is authoritative because the proxy routes on it, and it
// already carries the port whenever that port is non-default.
func buildBaseURL(r *http.Request) string {
	scheme := sanitizeHeaderValue(r.Header.Get("X-Forwarded-Proto"))
	if idx := strings.Index(scheme, ","); idx >= 0 {
		scheme = scheme[:idx]
	}
	scheme = strings.TrimSpace(scheme)
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	base := scheme + "://" + stripDefaultPort(scheme, sanitizeHeaderValue(r.Host))

	wsIDStr := chi.URLParam(r, "workspaceId")
	compatStr := chi.URLParam(r, "compat")

	base += "/ws/" + wsIDStr + "/scim/v2"
	if compatStr != "" {
		base += "/" + compatStr
	}

	return base
}

var headerSanitizer = regexp.MustCompile(`[\r\n]`)

func sanitizeHeaderValue(v string) string {
	return headerSanitizer.ReplaceAllString(v, "")
}

// stripDefaultPort keeps the authority canonical when a client spells out the default port.
func stripDefaultPort(scheme, host string) string {
	switch scheme {
	case "http":
		return strings.TrimSuffix(host, ":80")
	case "https":
		return strings.TrimSuffix(host, ":443")
	default:
		return host
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", ScimContentType)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func applyAttributeProjection(response map[string]any, attributes, excludedAttributes string) map[string]any {
	// Always remove password
	delete(response, "password")

	alwaysReturn := map[string]bool{"schemas": true, "id": true, "meta": true}

	if attributes != "" {
		attrList := parseAttrList(attributes)
		attrSet := make(map[string]bool)
		for _, a := range attrList {
			attrSet[resolveUrnPrefixedAttribute(a)] = true
		}
		for k := range response {
			if !alwaysReturn[k] && !attrSet[k] {
				delete(response, k)
			}
		}
	} else if excludedAttributes != "" {
		attrList := parseAttrList(excludedAttributes)
		for _, a := range attrList {
			resolved := resolveUrnPrefixedAttribute(a)
			if !alwaysReturn[resolved] {
				delete(response, resolved)
			}
		}
	}

	return response
}

func parseAttrList(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func resolveUrnPrefixedAttribute(attr string) string {
	enterprisePrefix := scim.EnterpriseSchemaURN + ":"
	if strings.HasPrefix(attr, enterprisePrefix) {
		return attr[len(enterprisePrefix):]
	}

	corePrefix := scim.UserSchemaURN + ":"
	if strings.HasPrefix(attr, corePrefix) {
		return attr[len(corePrefix):]
	}

	return attr
}

func getCompatMode(r *http.Request) scim.CompatMode {
	compatStr := chi.URLParam(r, "compat")
	return scim.ParseCompatMode(compatStr)
}
