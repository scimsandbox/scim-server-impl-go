package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

const (
	ScimContentType     = "application/scim+json"
	MaxRequestBodyBytes = int64(1 << 20) // 1 MiB (1,048,576 bytes)
)

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

func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return readJSONWithLimit(w, r, MaxRequestBodyBytes, v)
}

func readJSONWithLimit(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	if r.ContentLength > limit {
		return &http.MaxBytesError{Limit: limit}
	}
	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	r.Body = http.MaxBytesReader(w, body, limit)
	return json.NewDecoder(r.Body).Decode(v)
}

func writeReadJSONError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		scim.WriteScimError(w, scim.NewScimError(http.StatusRequestEntityTooLarge, "",
			fmt.Sprintf("Request body exceeds maximum allowed size (%d bytes)", maxBytesErr.Limit)))
		return
	}
	scim.WriteScimError(w, scim.NewScimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON"))
}

type projectionSpec struct {
	whole    map[string]bool
	subs     map[string]map[string]bool
	entAll   bool
	entWhole map[string]bool
	entSubs  map[string]map[string]bool
}

func parseProjectionSpec(raw string) projectionSpec {
	spec := projectionSpec{
		whole:    make(map[string]bool),
		subs:     make(map[string]map[string]bool),
		entWhole: make(map[string]bool),
		entSubs:  make(map[string]map[string]bool),
	}
	entURNLower := strings.ToLower(scim.EnterpriseSchemaURN)
	entPrefixLower := entURNLower + ":"
	userPrefixLower := strings.ToLower(scim.UserSchemaURN) + ":"
	groupPrefixLower := strings.ToLower(scim.GroupSchemaURN) + ":"

	for _, tok := range parseAttrList(raw) {
		lower := strings.ToLower(tok)
		if lower == entURNLower {
			spec.entAll = true
			continue
		}
		if strings.HasPrefix(lower, entPrefixLower) {
			rem := strings.TrimSpace(tok[len(entPrefixLower):])
			addPathToMaps(rem, spec.entWhole, spec.entSubs)
			continue
		}
		corePath := tok
		if strings.HasPrefix(lower, userPrefixLower) {
			corePath = strings.TrimSpace(tok[len(userPrefixLower):])
		} else if strings.HasPrefix(lower, groupPrefixLower) {
			corePath = strings.TrimSpace(tok[len(groupPrefixLower):])
		}
		addPathToMaps(corePath, spec.whole, spec.subs)
	}
	return spec
}

func addPathToMaps(attrPath string, whole map[string]bool, subs map[string]map[string]bool) {
	if attrPath == "" {
		return
	}
	parts := strings.SplitN(attrPath, ".", 2)
	parent := strings.ToLower(strings.TrimSpace(parts[0]))
	if parent == "" {
		return
	}
	if len(parts) == 1 {
		whole[parent] = true
		return
	}
	sub := strings.ToLower(strings.TrimSpace(parts[1]))
	if sub == "" {
		whole[parent] = true
		return
	}
	if subs[parent] == nil {
		subs[parent] = make(map[string]bool)
	}
	subs[parent][sub] = true
}

func toMapSlice(v any) ([]map[string]any, bool) {
	switch s := v.(type) {
	case []map[string]any:
		return s, true
	case []any:
		out := make([]map[string]any, 0, len(s))
		for _, elem := range s {
			m, ok := elem.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, m)
		}
		return out, true
	default:
		return nil, false
	}
}

func projectObjectMapWhitelist(m map[string]any, whole map[string]bool, subs map[string]map[string]bool, defaultKeep map[string]bool) {
	for k, v := range m {
		kl := strings.ToLower(k)
		if whole[kl] {
			continue
		}
		if subSet, hasSubs := subs[kl]; hasSubs {
			if subMap, ok := v.(map[string]any); ok {
				filtered := make(map[string]any)
				for sk, sv := range subMap {
					if subSet[strings.ToLower(sk)] {
						filtered[sk] = sv
					}
				}
				if len(filtered) > 0 {
					m[k] = filtered
				} else if !defaultKeep[kl] {
					delete(m, k)
				}
				continue
			}
			if sliceMaps, ok := toMapSlice(v); ok {
				projected := make([]map[string]any, 0, len(sliceMaps))
				for _, em := range sliceMaps {
					filtered := make(map[string]any)
					for sk, sv := range em {
						if subSet[strings.ToLower(sk)] {
							filtered[sk] = sv
						}
					}
					if len(filtered) > 0 {
						projected = append(projected, filtered)
					}
				}
				if len(projected) > 0 {
					m[k] = projected
				} else {
					delete(m, k)
				}
				continue
			}
		}
		if defaultKeep[kl] {
			continue
		}
		delete(m, k)
	}
}

func projectObjectMapBlacklist(m map[string]any, whole map[string]bool, subs map[string]map[string]bool, protected map[string]bool) {
	for k, v := range m {
		kl := strings.ToLower(k)
		if protected[kl] {
			continue
		}
		if whole[kl] {
			delete(m, k)
			continue
		}
		if subSet, hasSubs := subs[kl]; hasSubs {
			if subMap, ok := v.(map[string]any); ok {
				filtered := make(map[string]any, len(subMap))
				for sk, sv := range subMap {
					if !subSet[strings.ToLower(sk)] {
						filtered[sk] = sv
					}
				}
				if len(filtered) > 0 {
					m[k] = filtered
				} else {
					delete(m, k)
				}
				continue
			}
			if sliceMaps, ok := toMapSlice(v); ok {
				projected := make([]map[string]any, 0, len(sliceMaps))
				for _, em := range sliceMaps {
					filtered := make(map[string]any, len(em))
					for sk, sv := range em {
						if !subSet[strings.ToLower(sk)] {
							filtered[sk] = sv
						}
					}
					if len(filtered) > 0 {
						projected = append(projected, filtered)
					}
				}
				if len(projected) > 0 {
					m[k] = projected
				} else {
					delete(m, k)
				}
			}
		}
	}
}

func findKeyCaseInsensitive(m map[string]any, target string) (string, bool) {
	for k := range m {
		if strings.EqualFold(k, target) {
			return k, true
		}
	}
	return "", false
}

func applyAttributeProjection(response map[string]any, attributes, excludedAttributes string) map[string]any {
	// Always remove password (returned: never)
	delete(response, "password")

	if strings.TrimSpace(attributes) != "" {
		spec := parseProjectionSpec(attributes)

		// Handle enterprise extension block first
		if entKey, hasEnt := findKeyCaseInsensitive(response, scim.EnterpriseSchemaURN); hasEnt {
			if spec.entAll {
				// Keep entire enterprise extension map intact; mark it to survive core pruning
				spec.whole[strings.ToLower(entKey)] = true
			} else if len(spec.entWhole) > 0 || len(spec.entSubs) > 0 {
				if entMap, ok := response[entKey].(map[string]any); ok {
					entCopy := make(map[string]any, len(entMap))
					for ek, ev := range entMap {
						entCopy[ek] = ev
					}
					projectObjectMapWhitelist(entCopy, spec.entWhole, spec.entSubs, nil)
					if len(entCopy) > 0 {
						response[entKey] = entCopy
						spec.whole[strings.ToLower(entKey)] = true
					} else {
						delete(response, entKey)
					}
				} else {
					delete(response, entKey)
				}
			} else {
				delete(response, entKey)
			}
		}

		alwaysKeep := map[string]bool{"schemas": true, "id": true, "meta": true}
		// Never allow schemas or id to be stripped even via sub-attribute selector
		delete(spec.subs, "schemas")
		delete(spec.subs, "id")
		projectObjectMapWhitelist(response, spec.whole, spec.subs, alwaysKeep)
	} else if strings.TrimSpace(excludedAttributes) != "" {
		spec := parseProjectionSpec(excludedAttributes)

		if entKey, hasEnt := findKeyCaseInsensitive(response, scim.EnterpriseSchemaURN); hasEnt {
			if spec.entAll {
				delete(response, entKey)
			} else if len(spec.entWhole) > 0 || len(spec.entSubs) > 0 {
				if entMap, ok := response[entKey].(map[string]any); ok {
					entCopy := make(map[string]any, len(entMap))
					for ek, ev := range entMap {
						entCopy[ek] = ev
					}
					projectObjectMapBlacklist(entCopy, spec.entWhole, spec.entSubs, nil)
					if len(entCopy) > 0 {
						response[entKey] = entCopy
					} else {
						delete(response, entKey)
					}
				}
			}
		}

		protected := map[string]bool{
			"schemas":                             true,
			"id":                                  true,
			strings.ToLower(scim.EnterpriseSchemaURN): true,
		}
		projectObjectMapBlacklist(response, spec.whole, spec.subs, protected)
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

func getCompatMode(r *http.Request) scim.CompatMode {
	compatStr := chi.URLParam(r, "compat")
	return scim.ParseCompatMode(compatStr)
}

// checkETagMatch evaluates an If-Match or If-None-Match header against the resource version per RFC 7232 §3.1/§3.2 and RFC 7644 §3.14.
// If ifMatch is empty, or "*" (wildcard matching any existing resource representation), it returns true.
// Otherwise, it checks each comma-separated entity-tag token against "*" or the weak ETag representation W/"<version>".
func checkETagMatch(ifMatch string, version int64) bool {
	trimmed := strings.TrimSpace(ifMatch)
	if trimmed == "" || trimmed == "*" {
		return true
	}
	expected := fmt.Sprintf("W/\"%d\"", version)
	for _, part := range strings.Split(trimmed, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "*" || candidate == expected {
			return true
		}
	}
	return false
}
