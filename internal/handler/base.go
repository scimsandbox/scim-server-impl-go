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

func buildBaseURL(r *http.Request) string {
	scheme := sanitizeHeaderValue(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := sanitizeHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}

	port := sanitizeHeaderValue(r.Header.Get("X-Forwarded-Port"))

	base := scheme + "://" + host
	if port != "" && shouldAppendPort(scheme, port) {
		base += ":" + port
	}

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

func shouldAppendPort(scheme, port string) bool {
	if scheme == "http" && port == "80" {
		return false
	}
	if scheme == "https" && port == "443" {
		return false
	}
	return true
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
