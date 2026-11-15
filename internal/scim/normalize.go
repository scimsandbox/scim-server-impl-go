package scim

import (
	"slices"
	"strings"
)

const patchOpSchemaURN = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

var (
	userTopLevelCanonical = map[string]string{
		"schemas":           "schemas",
		"id":                "id",
		"externalid":        "externalId",
		"username":          "userName",
		"name":              "name",
		"displayname":       "displayName",
		"nickname":          "nickName",
		"profileurl":        "profileUrl",
		"title":             "title",
		"usertype":          "userType",
		"preferredlanguage": "preferredLanguage",
		"locale":            "locale",
		"timezone":          "timezone",
		"active":            "active",
		"password":          "password",
		"emails":            "emails",
		"phonenumbers":      "phoneNumbers",
		"ims":               "ims",
		"photos":            "photos",
		"addresses":         "addresses",
		"entitlements":      "entitlements",
		"roles":             "roles",
		"x509certificates":  "x509Certificates",
		"groups":            "groups",
		"meta":              "meta",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:user": EnterpriseSchemaURN,
	}

	nameSubAttrCanonical = map[string]string{
		"formatted":       "formatted",
		"familyname":      "familyName",
		"givenname":       "givenName",
		"middlename":      "middleName",
		"honorificprefix": "honorificPrefix",
		"honorificsuffix": "honorificSuffix",
	}

	multiValuedItemCanonical = map[string]string{
		"value":         "value",
		"display":       "display",
		"type":          "type",
		"primary":       "primary",
		"$ref":          "$ref",
		"formatted":     "formatted",
		"streetaddress": "streetAddress",
		"locality":      "locality",
		"region":        "region",
		"postalcode":    "postalCode",
		"country":       "country",
	}

	enterpriseSubAttrCanonical = map[string]string{
		"employeenumber": "employeeNumber",
		"costcenter":     "costCenter",
		"organization":   "organization",
		"division":       "division",
		"department":     "department",
		"manager":        "manager",
	}

	managerSubAttrCanonical = map[string]string{
		"value":       "value",
		"$ref":        "$ref",
		"displayname": "displayName",
	}

	groupTopLevelCanonical = map[string]string{
		"schemas":     "schemas",
		"id":          "id",
		"externalid":  "externalId",
		"displayname": "displayName",
		"members":     "members",
		"meta":        "meta",
	}

	groupMemberSubAttrCanonical = map[string]string{
		"value":   "value",
		"display": "display",
		"type":    "type",
		"$ref":    "$ref",
	}

	patchRequestCanonical = map[string]string{
		"schemas":    "schemas",
		"operations": "Operations",
	}

	patchOpCanonical = map[string]string{
		"op":    "op",
		"path":  "path",
		"value": "value",
	}
)

// ASCIILower converts ASCII 'A'..'Z' bytes to 'a'..'z' without folding
// non-ASCII Unicode characters (such as U+017F 'ſ' or U+212A 'K'), per RFC 7643 §2.1.
func ASCIILower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := make([]byte, len(s))
			copy(b, s[:i])
			for j := i; j < len(s); j++ {
				c := s[j]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				b[j] = c
			}
			return string(b)
		}
	}
	return s
}

func asciiLowerString(s string) string {
	return ASCIILower(s)
}

// ASCIIEqualFold reports whether a and b are equal under ASCII-only case folding.
func ASCIIEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca == cb {
			continue
		}
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func asciiEqualFold(a, b string) bool {
	return ASCIIEqualFold(a, b)
}

// asciiHasPrefixFold reports whether s starts with prefix under ASCII-only case folding.
func asciiHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return asciiEqualFold(s[:len(prefix)], prefix)
}

// StripCoreUserURNPrefix strips an optional "urn:ietf:params:scim:schemas:core:2.0:User:"
// prefix using ASCII-only case folding.
func StripCoreUserURNPrefix(s string) (string, bool) {
	prefixLen := len(UserSchemaURN) + 1
	if len(s) >= prefixLen && s[len(UserSchemaURN)] == ':' && asciiEqualFold(s[:len(UserSchemaURN)], UserSchemaURN) {
		return s[prefixLen:], true
	}
	return s, false
}

// StripGroupURNPrefix strips an optional "urn:ietf:params:scim:schemas:core:2.0:Group:"
// prefix using ASCII-only case folding.
func StripGroupURNPrefix(s string) (string, bool) {
	prefixLen := len(GroupSchemaURN) + 1
	if len(s) >= prefixLen && s[len(GroupSchemaURN)] == ':' && asciiEqualFold(s[:len(GroupSchemaURN)], GroupSchemaURN) {
		return s[prefixLen:], true
	}
	return s, false
}

type normCandidate struct {
	groupKey  string
	targetKey string
	tier      int // 3 = exact canonical unprefixed, 2 = unprefixed case variant, 1 = URN-prefixed, 0 = nested core-URN object
	subTier   int // within tier 0: 1 = exact canonical inner key, 0 = case-variant inner key
	outerKey  string
	innerKey  string
	val       any
}

// candBetter reports whether candidate a has strictly higher precedence than b.
func candBetter(a, b normCandidate) bool {
	if a.tier != b.tier {
		return a.tier > b.tier
	}
	if a.subTier != b.subTier {
		return a.subTier > b.subTier
	}
	if cmp := strings.Compare(a.outerKey, b.outerKey); cmp != 0 {
		return cmp < 0
	}
	return strings.Compare(a.innerKey, b.innerKey) < 0
}

func normalizeObjectWithSchema(input map[string]any, canonicalMap map[string]string, coreSchemaURN string) map[string]any {
	if input == nil {
		return nil
	}

	outerKeys := make([]string, 0, len(input))
	for k := range input {
		outerKeys = append(outerKeys, k)
	}
	slices.Sort(outerKeys)

	winners := make(map[string]normCandidate, len(input))
	upsert := func(c normCandidate) {
		if cur, exists := winners[c.groupKey]; !exists || candBetter(c, cur) {
			winners[c.groupKey] = c
		}
	}

	corePrefixLen := len(coreSchemaURN) + 1
	for _, outerKey := range outerKeys {
		val := input[outerKey]

		if coreSchemaURN != "" && asciiEqualFold(outerKey, coreSchemaURN) {
			if val == nil {
				continue
			}
			if subMap, ok := val.(map[string]any); ok {
				innerKeys := make([]string, 0, len(subMap))
				for ik := range subMap {
					innerKeys = append(innerKeys, ik)
				}
				slices.Sort(innerKeys)
				for _, innerKey := range innerKeys {
					lowerInner := asciiLowerString(innerKey)
					targetKey := innerKey
					subTier := 0
					if canon, known := canonicalMap[lowerInner]; known {
						targetKey = canon
						if innerKey == canon {
							subTier = 1
						}
					} else if innerKey == lowerInner {
						subTier = 1
					}
					upsert(normCandidate{
						groupKey:  lowerInner,
						targetKey: targetKey,
						tier:      0,
						subTier:   subTier,
						outerKey:  outerKey,
						innerKey:  innerKey,
						val:       subMap[innerKey],
					})
				}
				continue
			}
			// Preserve non-map value on coreSchemaURN so callers that validate object types can reject it.
			upsert(normCandidate{
				groupKey:  asciiLowerString(coreSchemaURN),
				targetKey: coreSchemaURN,
				tier:      3,
				outerKey:  outerKey,
				val:       val,
			})
			continue
		}

		if coreSchemaURN != "" && len(outerKey) >= corePrefixLen && outerKey[len(coreSchemaURN)] == ':' && asciiEqualFold(outerKey[:len(coreSchemaURN)], coreSchemaURN) {
			suffix := outerKey[corePrefixLen:]
			lowerSuffix := asciiLowerString(suffix)
			targetKey := suffix
			if canon, known := canonicalMap[lowerSuffix]; known {
				targetKey = canon
			}
			upsert(normCandidate{
				groupKey:  lowerSuffix,
				targetKey: targetKey,
				tier:      1,
				outerKey:  outerKey,
				val:       val,
			})
			continue
		}

		lowerKey := asciiLowerString(outerKey)
		targetKey := outerKey
		tier := 2
		if canon, known := canonicalMap[lowerKey]; known {
			targetKey = canon
			if outerKey == canon {
				tier = 3
			}
		} else if outerKey == lowerKey {
			tier = 3
		}
		upsert(normCandidate{
			groupKey:  lowerKey,
			targetKey: targetKey,
			tier:      tier,
			outerKey:  outerKey,
			val:       val,
		})
	}

	out := make(map[string]any, len(winners))
	for _, w := range winners {
		out[w.targetKey] = w.val
	}
	return out
}

func normalizeCollectionSlice(raw any, itemNormFn func(map[string]any) map[string]any) any {
	switch s := raw.(type) {
	case []any:
		res := make([]any, len(s))
		for i, elem := range s {
			if m, ok := elem.(map[string]any); ok {
				res[i] = itemNormFn(m)
			} else {
				res[i] = elem
			}
		}
		return res
	case []map[string]any:
		res := make([]map[string]any, len(s))
		for i, m := range s {
			res[i] = itemNormFn(m)
		}
		return res
	default:
		return raw
	}
}

// NormalizeNameMap canonicalizes sub-attribute keys of a SCIM User.name object.
func NormalizeNameMap(m map[string]any) map[string]any {
	return normalizeObjectWithSchema(m, nameSubAttrCanonical, "")
}

// NormalizeMultiValuedItemMap canonicalizes sub-attribute keys of a SCIM multi-valued complex element.
func NormalizeMultiValuedItemMap(m map[string]any) map[string]any {
	return normalizeObjectWithSchema(m, multiValuedItemCanonical, "")
}

// NormalizeManagerMap canonicalizes sub-attribute keys of an Enterprise User manager object.
func NormalizeManagerMap(m map[string]any) map[string]any {
	return normalizeObjectWithSchema(m, managerSubAttrCanonical, "")
}

// NormalizeEnterpriseMap canonicalizes sub-attribute keys of an Enterprise User extension object.
func NormalizeEnterpriseMap(m map[string]any) map[string]any {
	out := normalizeObjectWithSchema(m, enterpriseSubAttrCanonical, "")
	if mgrMap, ok := out["manager"].(map[string]any); ok {
		out["manager"] = NormalizeManagerMap(mgrMap)
	}
	return out
}

// NormalizeUserInput canonicalizes SCIM User input attribute keys (RFC 7643 §2.1) using
// ASCII-only case folding, stripping optional core User URN prefixes and merging nested
// core User URN extension objects with deterministic precedence:
// exact canonical unprefixed > unprefixed case variant > URN-prefixed > nested core-URN object,
// tie-broken lexicographically.
func NormalizeUserInput(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := normalizeObjectWithSchema(input, userTopLevelCanonical, UserSchemaURN)

	// Fold flat EnterpriseSchemaURN:<attr> keys into EnterpriseSchemaURN when EnterpriseSchemaURN
	// is absent, nil, or an object (preserving non-object values so validation rejects them).
	entPrefixLen := len(EnterpriseSchemaURN) + 1
	var flatEntKeys []string
	for k := range out {
		if len(k) >= entPrefixLen && k[len(EnterpriseSchemaURN)] == ':' && asciiEqualFold(k[:len(EnterpriseSchemaURN)], EnterpriseSchemaURN) {
			flatEntKeys = append(flatEntKeys, k)
		}
	}
	if len(flatEntKeys) > 0 {
		slices.Sort(flatEntKeys)
		existingExt, hasExt := out[EnterpriseSchemaURN]
		extMap, extIsMap := existingExt.(map[string]any)
		if !hasExt || existingExt == nil || extIsMap {
			merged := make(map[string]any)
			if extIsMap {
				for k, v := range NormalizeEnterpriseMap(extMap) {
					merged[k] = v
				}
			}
			flatWinners := make(map[string]normCandidate, len(flatEntKeys))
			for _, fk := range flatEntKeys {
				suffix := fk[entPrefixLen:]
				lowerSuffix := asciiLowerString(suffix)
				targetKey := suffix
				if canon, known := enterpriseSubAttrCanonical[lowerSuffix]; known {
					targetKey = canon
				}
				cand := normCandidate{
					groupKey:  lowerSuffix,
					targetKey: targetKey,
					tier:      1,
					outerKey:  fk,
					val:       out[fk],
				}
				if cur, exists := flatWinners[lowerSuffix]; !exists || candBetter(cand, cur) {
					flatWinners[lowerSuffix] = cand
				}
				delete(out, fk)
			}
			for _, fw := range flatWinners {
				if _, alreadyInExplicitMap := merged[fw.targetKey]; !alreadyInExplicitMap {
					val := fw.val
					if fw.targetKey == "manager" {
						if mm, ok := val.(map[string]any); ok {
							val = NormalizeManagerMap(mm)
						}
					}
					merged[fw.targetKey] = val
				}
			}
			out[EnterpriseSchemaURN] = merged
		}
	} else if extMap, ok := out[EnterpriseSchemaURN].(map[string]any); ok {
		out[EnterpriseSchemaURN] = NormalizeEnterpriseMap(extMap)
	}

	if nm, ok := out["name"].(map[string]any); ok {
		out["name"] = NormalizeNameMap(nm)
	}

	for _, colKey := range []string{
		"emails", "phoneNumbers", "ims", "photos",
		"addresses", "entitlements", "roles", "x509Certificates",
	} {
		if rawCol, ok := out[colKey]; ok && rawCol != nil {
			out[colKey] = normalizeCollectionSlice(rawCol, NormalizeMultiValuedItemMap)
		}
	}

	return out
}

// NormalizeGroupMemberMap canonicalizes sub-attribute keys of a SCIM Group.members element.
func NormalizeGroupMemberMap(m map[string]any) map[string]any {
	return normalizeObjectWithSchema(m, groupMemberSubAttrCanonical, "")
}

// NormalizeGroupInput canonicalizes SCIM Group input attribute keys (RFC 7643 §2.1) using
// ASCII-only case folding, stripping optional core Group URN prefixes and merging nested
// core Group URN extension objects with deterministic precedence.
func NormalizeGroupInput(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := normalizeObjectWithSchema(input, groupTopLevelCanonical, GroupSchemaURN)
	if rawMembers, ok := out["members"]; ok && rawMembers != nil {
		out["members"] = normalizeCollectionSlice(rawMembers, NormalizeGroupMemberMap)
	}
	return out
}

// NormalizePatchRequest canonicalizes top-level keys ("schemas", "Operations") of a SCIM PatchOp request.
func NormalizePatchRequest(req map[string]any) map[string]any {
	return normalizeObjectWithSchema(req, patchRequestCanonical, "")
}

// NormalizePatchOperation canonicalizes keys ("op", "path", "value") of a single SCIM PATCH operation.
func NormalizePatchOperation(op map[string]any) map[string]any {
	return normalizeObjectWithSchema(op, patchOpCanonical, "")
}
