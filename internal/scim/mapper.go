package scim

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

const (
	UserSchemaURN       = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchemaURN      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	EnterpriseSchemaURN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

func UserToScimResponse(user *model.ScimUser, baseURL string, groups []map[string]any) map[string]any {
	result := make(map[string]any)

	schemas := []string{UserSchemaURN}
	if hasEnterpriseData(user) {
		schemas = append(schemas, EnterpriseSchemaURN)
	}
	result["schemas"] = schemas
	result["id"] = user.ID.String()

	putIfNotNull(result, "externalId", user.ExternalID)
	result["userName"] = user.UserName

	nameMap := buildNameMap(user)
	if len(nameMap) > 0 {
		result["name"] = nameMap
	}

	putIfNotNull(result, "displayName", user.DisplayName)
	putIfNotNull(result, "nickName", user.NickName)
	putIfNotNull(result, "profileUrl", user.ProfileUrl)
	putIfNotNull(result, "title", user.Title)
	putIfNotNull(result, "userType", user.UserType)
	putIfNotNull(result, "preferredLanguage", user.PreferredLanguage)
	putIfNotNull(result, "locale", user.Locale)
	putIfNotNull(result, "timezone", user.Timezone)
	result["active"] = user.Active

	putCollection(result, "emails", emailsToMaps(user.Emails))
	putCollection(result, "phoneNumbers", phoneNumbersToMaps(user.PhoneNumbers))
	putCollection(result, "ims", imsToMaps(user.Ims))
	putCollection(result, "photos", photosToMaps(user.Photos))
	putCollection(result, "addresses", addressesToMaps(user.Addresses))
	putCollection(result, "entitlements", entitlementsToMaps(user.Entitlements))
	putCollection(result, "roles", rolesToMaps(user.Roles))
	putCollection(result, "x509Certificates", x509CertificatesToMaps(user.X509Certificates))

	if len(groups) > 0 {
		result["groups"] = groups
	}

	if hasEnterpriseData(user) {
		ext := make(map[string]any)
		putIfNotNull(ext, "employeeNumber", user.EnterpriseEmployeeNumber)
		putIfNotNull(ext, "costCenter", user.EnterpriseCostCenter)
		putIfNotNull(ext, "organization", user.EnterpriseOrganization)
		putIfNotNull(ext, "division", user.EnterpriseDivision)
		putIfNotNull(ext, "department", user.EnterpriseDepartment)
		mgrMap := buildManagerMap(user)
		if len(mgrMap) > 0 {
			ext["manager"] = mgrMap
		}
		result[EnterpriseSchemaURN] = ext
	}

	result["meta"] = buildUserMeta(user, baseURL)

	return result
}

func ApplyFromScimInput(user *model.ScimUser, input map[string]any) error {
	if err := applySimpleAttributes(user, input); err != nil {
		return err
	}
	if err := applyNameAttribute(user, input); err != nil {
		return err
	}

	if v, ok := input["emails"]; ok {
		col, err := replaceCollectionEmails(v)
		if err != nil {
			return err
		}
		user.Emails = col
	}
	if v, ok := input["phoneNumbers"]; ok {
		col, err := replaceCollectionPhoneNumbers(v)
		if err != nil {
			return err
		}
		user.PhoneNumbers = col
	}
	if v, ok := input["addresses"]; ok {
		col, err := replaceCollectionAddresses(v)
		if err != nil {
			return err
		}
		user.Addresses = col
	}
	if v, ok := input["ims"]; ok {
		col, err := replaceCollectionIms(v)
		if err != nil {
			return err
		}
		user.Ims = col
	}
	if v, ok := input["photos"]; ok {
		col, err := replaceCollectionPhotos(v)
		if err != nil {
			return err
		}
		user.Photos = col
	}
	if v, ok := input["entitlements"]; ok {
		col, err := replaceCollectionEntitlements(v)
		if err != nil {
			return err
		}
		user.Entitlements = col
	}
	if v, ok := input["roles"]; ok {
		col, err := replaceCollectionRoles(v)
		if err != nil {
			return err
		}
		user.Roles = col
	}
	if v, ok := input["x509Certificates"]; ok {
		col, err := replaceCollectionX509Certificates(v)
		if err != nil {
			return err
		}
		user.X509Certificates = col
	}

	if err := applyEnterpriseExtension(user, input); err != nil {
		return err
	}
	return nil
}

func ClearMutableAttributes(user *model.ScimUser) {
	user.ExternalID = nil
	user.NameFormatted = nil
	user.NameFamilyName = nil
	user.NameGivenName = nil
	user.NameMiddleName = nil
	user.NameHonorificPrefix = nil
	user.NameHonorificSuffix = nil
	user.DisplayName = nil
	user.NickName = nil
	user.ProfileUrl = nil
	user.Title = nil
	user.UserType = nil
	user.PreferredLanguage = nil
	user.Locale = nil
	user.Timezone = nil
	user.Active = true
	user.Password = nil
	user.Emails = nil
	user.PhoneNumbers = nil
	user.Addresses = nil
	user.Ims = nil
	user.Photos = nil
	user.Entitlements = nil
	user.Roles = nil
	user.X509Certificates = nil
	user.EnterpriseEmployeeNumber = nil
	user.EnterpriseCostCenter = nil
	user.EnterpriseOrganization = nil
	user.EnterpriseDivision = nil
	user.EnterpriseDepartment = nil
	user.EnterpriseManagerValue = nil
	user.EnterpriseManagerRef = nil
	user.EnterpriseManagerDisplay = nil
}

// CloneScimUser returns a deep copy of a ScimUser for before/after mutation comparison.
func CloneScimUser(u *model.ScimUser) *model.ScimUser {
	if u == nil {
		return nil
	}
	cp := *u
	cp.ExternalID = cloneStrPtr(u.ExternalID)
	cp.NameFormatted = cloneStrPtr(u.NameFormatted)
	cp.NameFamilyName = cloneStrPtr(u.NameFamilyName)
	cp.NameGivenName = cloneStrPtr(u.NameGivenName)
	cp.NameMiddleName = cloneStrPtr(u.NameMiddleName)
	cp.NameHonorificPrefix = cloneStrPtr(u.NameHonorificPrefix)
	cp.NameHonorificSuffix = cloneStrPtr(u.NameHonorificSuffix)
	cp.DisplayName = cloneStrPtr(u.DisplayName)
	cp.NickName = cloneStrPtr(u.NickName)
	cp.ProfileUrl = cloneStrPtr(u.ProfileUrl)
	cp.Title = cloneStrPtr(u.Title)
	cp.UserType = cloneStrPtr(u.UserType)
	cp.PreferredLanguage = cloneStrPtr(u.PreferredLanguage)
	cp.Locale = cloneStrPtr(u.Locale)
	cp.Timezone = cloneStrPtr(u.Timezone)
	cp.Password = cloneStrPtr(u.Password)
	cp.EnterpriseEmployeeNumber = cloneStrPtr(u.EnterpriseEmployeeNumber)
	cp.EnterpriseCostCenter = cloneStrPtr(u.EnterpriseCostCenter)
	cp.EnterpriseOrganization = cloneStrPtr(u.EnterpriseOrganization)
	cp.EnterpriseDivision = cloneStrPtr(u.EnterpriseDivision)
	cp.EnterpriseDepartment = cloneStrPtr(u.EnterpriseDepartment)
	cp.EnterpriseManagerValue = cloneStrPtr(u.EnterpriseManagerValue)
	cp.EnterpriseManagerRef = cloneStrPtr(u.EnterpriseManagerRef)
	cp.EnterpriseManagerDisplay = cloneStrPtr(u.EnterpriseManagerDisplay)

	if u.Emails != nil {
		cp.Emails = append([]model.ScimUserEmail(nil), u.Emails...)
	}
	if u.PhoneNumbers != nil {
		cp.PhoneNumbers = append([]model.ScimUserPhoneNumber(nil), u.PhoneNumbers...)
	}
	if u.Addresses != nil {
		cp.Addresses = append([]model.ScimUserAddress(nil), u.Addresses...)
	}
	if u.Entitlements != nil {
		cp.Entitlements = append([]model.ScimUserEntitlement(nil), u.Entitlements...)
	}
	if u.Roles != nil {
		cp.Roles = append([]model.ScimUserRole(nil), u.Roles...)
	}
	if u.Ims != nil {
		cp.Ims = append([]model.ScimUserIm(nil), u.Ims...)
	}
	if u.Photos != nil {
		cp.Photos = append([]model.ScimUserPhoto(nil), u.Photos...)
	}
	if u.X509Certificates != nil {
		cp.X509Certificates = append([]model.ScimUserX509Certificate(nil), u.X509Certificates...)
	}
	return &cp
}

func cloneStrPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}

func strPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func sliceEqual[T any](a, b []T) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// ScimUserMutableEqual reports whether all mutable SCIM attributes of a and b are identical.
func ScimUserMutableEqual(a, b *model.ScimUser) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.UserName == b.UserName &&
		strPtrEqual(a.ExternalID, b.ExternalID) &&
		strPtrEqual(a.NameFormatted, b.NameFormatted) &&
		strPtrEqual(a.NameFamilyName, b.NameFamilyName) &&
		strPtrEqual(a.NameGivenName, b.NameGivenName) &&
		strPtrEqual(a.NameMiddleName, b.NameMiddleName) &&
		strPtrEqual(a.NameHonorificPrefix, b.NameHonorificPrefix) &&
		strPtrEqual(a.NameHonorificSuffix, b.NameHonorificSuffix) &&
		strPtrEqual(a.DisplayName, b.DisplayName) &&
		strPtrEqual(a.NickName, b.NickName) &&
		strPtrEqual(a.ProfileUrl, b.ProfileUrl) &&
		strPtrEqual(a.Title, b.Title) &&
		strPtrEqual(a.UserType, b.UserType) &&
		strPtrEqual(a.PreferredLanguage, b.PreferredLanguage) &&
		strPtrEqual(a.Locale, b.Locale) &&
		strPtrEqual(a.Timezone, b.Timezone) &&
		a.Active == b.Active &&
		strPtrEqual(a.Password, b.Password) &&
		strPtrEqual(a.EnterpriseEmployeeNumber, b.EnterpriseEmployeeNumber) &&
		strPtrEqual(a.EnterpriseCostCenter, b.EnterpriseCostCenter) &&
		strPtrEqual(a.EnterpriseOrganization, b.EnterpriseOrganization) &&
		strPtrEqual(a.EnterpriseDivision, b.EnterpriseDivision) &&
		strPtrEqual(a.EnterpriseDepartment, b.EnterpriseDepartment) &&
		strPtrEqual(a.EnterpriseManagerValue, b.EnterpriseManagerValue) &&
		strPtrEqual(a.EnterpriseManagerRef, b.EnterpriseManagerRef) &&
		strPtrEqual(a.EnterpriseManagerDisplay, b.EnterpriseManagerDisplay) &&
		sliceEqual(a.Emails, b.Emails) &&
		sliceEqual(a.PhoneNumbers, b.PhoneNumbers) &&
		sliceEqual(a.Addresses, b.Addresses) &&
		sliceEqual(a.Entitlements, b.Entitlements) &&
		sliceEqual(a.Roles, b.Roles) &&
		sliceEqual(a.Ims, b.Ims) &&
		sliceEqual(a.Photos, b.Photos) &&
		sliceEqual(a.X509Certificates, b.X509Certificates)
}

func hasEnterpriseData(user *model.ScimUser) bool {
	return user.EnterpriseEmployeeNumber != nil ||
		user.EnterpriseCostCenter != nil ||
		user.EnterpriseOrganization != nil ||
		user.EnterpriseDivision != nil ||
		user.EnterpriseDepartment != nil ||
		user.EnterpriseManagerValue != nil
}

func buildNameMap(user *model.ScimUser) map[string]any {
	nm := make(map[string]any)
	putIfNotNull(nm, "formatted", user.NameFormatted)
	putIfNotNull(nm, "familyName", user.NameFamilyName)
	putIfNotNull(nm, "givenName", user.NameGivenName)
	putIfNotNull(nm, "middleName", user.NameMiddleName)
	putIfNotNull(nm, "honorificPrefix", user.NameHonorificPrefix)
	putIfNotNull(nm, "honorificSuffix", user.NameHonorificSuffix)
	return nm
}

func buildManagerMap(user *model.ScimUser) map[string]any {
	mm := make(map[string]any)
	putIfNotNull(mm, "value", user.EnterpriseManagerValue)
	putIfNotNull(mm, "$ref", user.EnterpriseManagerRef)
	putIfNotNull(mm, "displayName", user.EnterpriseManagerDisplay)
	return mm
}

func buildUserMeta(user *model.ScimUser, baseURL string) map[string]any {
	return map[string]any{
		"resourceType": "User",
		"created":      user.CreatedAt.UTC().Format(time.RFC3339),
		"lastModified": user.LastModified.UTC().Format(time.RFC3339),
		"location":     baseURL + "/Users/" + user.ID.String(),
		"version":      fmt.Sprintf("W/\"%d\"", user.Version),
	}
}

func putIfNotNull(m map[string]any, key string, val *string) {
	if val != nil {
		m[key] = *val
	}
}

func putCollection(m map[string]any, key string, items []map[string]any) {
	if len(items) > 0 {
		m[key] = items
	}
}

func applySimpleAttributes(user *model.ScimUser, input map[string]any) error {
	if rawUN, ok := input["userName"]; ok && rawUN != nil {
		s, err := parseStrictStringPtr(rawUN, "userName")
		if err != nil {
			return err
		}
		if s == nil || *s == "" {
			return NewScimError(400, "invalidValue", "userName is required")
		}
		user.UserName = *s
	} else if _, ok := input["userName"]; ok && input["userName"] == nil {
		return NewScimError(400, "invalidValue", "userName is required")
	}
	if v, ok := input["externalId"]; ok {
		s, err := parseStrictStringPtr(v, "externalId")
		if err != nil {
			return err
		}
		user.ExternalID = s
	}
	if v, ok := input["displayName"]; ok {
		s, err := parseStrictStringPtr(v, "displayName")
		if err != nil {
			return err
		}
		user.DisplayName = s
	}
	if v, ok := input["nickName"]; ok {
		s, err := parseStrictStringPtr(v, "nickName")
		if err != nil {
			return err
		}
		user.NickName = s
	}
	if v, ok := input["profileUrl"]; ok {
		s, err := parseStrictStringPtr(v, "profileUrl")
		if err != nil {
			return err
		}
		if s != nil && *s != "" {
			if err := validateReference(*s); err != nil {
				return err
			}
		}
		user.ProfileUrl = s
	}
	if v, ok := input["title"]; ok {
		s, err := parseStrictStringPtr(v, "title")
		if err != nil {
			return err
		}
		user.Title = s
	}
	if v, ok := input["userType"]; ok {
		s, err := parseStrictStringPtr(v, "userType")
		if err != nil {
			return err
		}
		user.UserType = s
	}
	if v, ok := input["preferredLanguage"]; ok {
		s, err := parseStrictStringPtr(v, "preferredLanguage")
		if err != nil {
			return err
		}
		user.PreferredLanguage = s
	}
	if v, ok := input["locale"]; ok {
		s, err := parseStrictStringPtr(v, "locale")
		if err != nil {
			return err
		}
		user.Locale = s
	}
	if v, ok := input["timezone"]; ok {
		s, err := parseStrictStringPtr(v, "timezone")
		if err != nil {
			return err
		}
		user.Timezone = s
	}
	if v, ok := input["active"]; ok && v != nil {
		b, err := parseStrictBool(v, "active")
		if err != nil {
			return err
		}
		user.Active = b
	} else {
		user.Active = true
	}
	rawPw, hasPw, err := extractAndValidatePassword(input)
	if err != nil {
		return err
	}
	if hasPw {
		pw, err := HashPassword(rawPw)
		if err != nil {
			return err
		}
		user.Password = pw
	}
	return nil
}

func applyNameAttribute(user *model.ScimUser, input map[string]any) error {
	nameRaw, ok := input["name"]
	if !ok || nameRaw == nil {
		return nil
	}
	nameMap, ok := nameRaw.(map[string]any)
	if !ok {
		return NewScimError(400, "invalidValue", "Attribute 'name' must be an object")
	}
	if v, ok := nameMap["formatted"]; ok {
		s, err := parseStrictStringPtr(v, "name.formatted")
		if err != nil {
			return err
		}
		user.NameFormatted = s
	}
	if v, ok := nameMap["familyName"]; ok {
		s, err := parseStrictStringPtr(v, "name.familyName")
		if err != nil {
			return err
		}
		user.NameFamilyName = s
	}
	if v, ok := nameMap["givenName"]; ok {
		s, err := parseStrictStringPtr(v, "name.givenName")
		if err != nil {
			return err
		}
		user.NameGivenName = s
	}
	if v, ok := nameMap["middleName"]; ok {
		s, err := parseStrictStringPtr(v, "name.middleName")
		if err != nil {
			return err
		}
		user.NameMiddleName = s
	}
	if v, ok := nameMap["honorificPrefix"]; ok {
		s, err := parseStrictStringPtr(v, "name.honorificPrefix")
		if err != nil {
			return err
		}
		user.NameHonorificPrefix = s
	}
	if v, ok := nameMap["honorificSuffix"]; ok {
		s, err := parseStrictStringPtr(v, "name.honorificSuffix")
		if err != nil {
			return err
		}
		user.NameHonorificSuffix = s
	}
	return nil
}

func applyEnterpriseExtension(user *model.ScimUser, input map[string]any) error {
	var extRaw any
	found := false
	for k, val := range input {
		if strings.EqualFold(k, EnterpriseSchemaURN) {
			extRaw = val
			found = true
			break
		}
	}
	if !found || extRaw == nil {
		return nil
	}
	ext, ok := extRaw.(map[string]any)
	if !ok {
		return NewScimError(400, "invalidValue", "Enterprise extension must be an object")
	}
	if v, ok := ext["employeeNumber"]; ok {
		s, err := parseStrictStringPtr(v, "employeeNumber")
		if err != nil {
			return err
		}
		user.EnterpriseEmployeeNumber = s
	}
	if v, ok := ext["costCenter"]; ok {
		s, err := parseStrictStringPtr(v, "costCenter")
		if err != nil {
			return err
		}
		user.EnterpriseCostCenter = s
	}
	if v, ok := ext["organization"]; ok {
		s, err := parseStrictStringPtr(v, "organization")
		if err != nil {
			return err
		}
		user.EnterpriseOrganization = s
	}
	if v, ok := ext["division"]; ok {
		s, err := parseStrictStringPtr(v, "division")
		if err != nil {
			return err
		}
		user.EnterpriseDivision = s
	}
	if v, ok := ext["department"]; ok {
		s, err := parseStrictStringPtr(v, "department")
		if err != nil {
			return err
		}
		user.EnterpriseDepartment = s
	}
	if mgrRaw, ok := ext["manager"]; ok {
		if err := applyEnterpriseManager(user, mgrRaw); err != nil {
			return err
		}
	}
	return nil
}

// ExtractUUIDFromRef extracts a canonical lowercase resource UUID from a SCIM $ref URI
// (RFC 7643 §2.4), accepting absolute or relative URIs with versioned (e.g., .../scim/v1/Users/<id>,
// .../scim/v2/Users/<id>) or unversioned (e.g., /Users/<id>, /Groups/<id>) paths.
// Returns "" if ref does not contain a path ending in a valid UUID.
func ExtractUUIDFromRef(ref string) string {
	s := strings.TrimSpace(ref)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if schemeIdx := strings.Index(s, "://"); schemeIdx >= 0 {
		rest := s[schemeIdx+3:]
		slashIdx := strings.IndexByte(rest, '/')
		if slashIdx < 0 {
			return ""
		}
		s = rest[slashIdx:]
	}
	s = strings.TrimRight(s, "/")
	idx := strings.LastIndexByte(s, '/')
	if idx < 0 || idx+1 >= len(s) {
		return ""
	}
	candidate := s[idx+1:]
	if parsed, err := uuid.Parse(candidate); err == nil {
		return parsed.String()
	}
	return ""
}

func applyEnterpriseManager(user *model.ScimUser, mgrRaw any) error {
	if mgrRaw == nil {
		user.EnterpriseManagerValue = nil
		user.EnterpriseManagerRef = nil
		user.EnterpriseManagerDisplay = nil
		return nil
	}
	switch mgr := mgrRaw.(type) {
	case string:
		normStr := NormalizeNFC(mgr)
		user.EnterpriseManagerValue = &normStr
		user.EnterpriseManagerDisplay = nil
	case map[string]any:
		var parsedVal *string
		valProvided := false
		if v, ok := mgr["value"]; ok {
			valProvided = true
			s, err := parseStrictStringPtr(v, "manager.value")
			if err != nil {
				return err
			}
			parsedVal = s
			user.EnterpriseManagerValue = s
		}
		if v, ok := mgr["$ref"]; ok {
			s, err := parseStrictStringPtr(v, "manager.$ref")
			if err != nil {
				return err
			}
			user.EnterpriseManagerRef = s
			if s != nil && strings.TrimSpace(*s) != "" {
				refUUID := ExtractUUIDFromRef(*s)
				if valProvided && parsedVal != nil && strings.TrimSpace(*parsedVal) != "" {
					if refUUID != "" && !strings.EqualFold(refUUID, strings.TrimSpace(*parsedVal)) {
						return NewScimError(400, "invalidValue", "manager.value and manager.$ref refer to different resource IDs")
					}
				} else if refUUID != "" && (!valProvided || user.EnterpriseManagerValue == nil || strings.TrimSpace(*user.EnterpriseManagerValue) == "") {
					user.EnterpriseManagerValue = &refUUID
				}
			}
		}
		// RFC 7643 §4.3: manager.displayName has mutability "readOnly" and MUST be ignored in client input.
		user.EnterpriseManagerDisplay = nil
	default:
		return NewScimError(400, "invalidValue", "Attribute 'manager' must be an object or string")
	}
	return nil
}

// Collection replace helpers

func extractMapSlice(v any, attrName string) ([]map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	switch raw := v.(type) {
	case []any:
		res := make([]map[string]any, 0, len(raw))
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, NewScimError(400, "invalidValue", fmt.Sprintf("Elements of '%s' must be JSON objects", attrName))
			}
			res = append(res, m)
		}
		return res, nil
	case []map[string]any:
		return raw, nil
	default:
		return nil, NewScimError(400, "invalidValue", fmt.Sprintf("Attribute '%s' must be an array", attrName))
	}
}

func replaceCollectionEmails(v any) ([]model.ScimUserEmail, error) {
	items, err := extractMapSlice(v, "emails")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserEmail, 0, len(items))
	for _, m := range items {
		built, err := buildEmail(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicateEmails(result), nil
}

func replaceCollectionPhoneNumbers(v any) ([]model.ScimUserPhoneNumber, error) {
	items, err := extractMapSlice(v, "phoneNumbers")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserPhoneNumber, 0, len(items))
	for _, m := range items {
		built, err := buildPhoneNumber(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicatePhoneNumbers(result), nil
}

func replaceCollectionAddresses(v any) ([]model.ScimUserAddress, error) {
	items, err := extractMapSlice(v, "addresses")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserAddress, 0, len(items))
	for _, m := range items {
		built, err := buildAddress(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicateAddresses(result), nil
}

func replaceCollectionIms(v any) ([]model.ScimUserIm, error) {
	items, err := extractMapSlice(v, "ims")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserIm, 0, len(items))
	for _, m := range items {
		built, err := buildIm(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicateIms(result), nil
}

func replaceCollectionPhotos(v any) ([]model.ScimUserPhoto, error) {
	items, err := extractMapSlice(v, "photos")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserPhoto, 0, len(items))
	for _, m := range items {
		built, err := buildPhoto(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicatePhotos(result), nil
}

func replaceCollectionEntitlements(v any) ([]model.ScimUserEntitlement, error) {
	items, err := extractMapSlice(v, "entitlements")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserEntitlement, 0, len(items))
	for _, m := range items {
		built, err := buildEntitlement(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicateEntitlements(result), nil
}

func replaceCollectionRoles(v any) ([]model.ScimUserRole, error) {
	items, err := extractMapSlice(v, "roles")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserRole, 0, len(items))
	for _, m := range items {
		built, err := buildRole(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicateRoles(result), nil
}

func replaceCollectionX509Certificates(v any) ([]model.ScimUserX509Certificate, error) {
	items, err := extractMapSlice(v, "x509Certificates")
	if err != nil || items == nil {
		return nil, err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return nil, err
	}
	result := make([]model.ScimUserX509Certificate, 0, len(items))
	for _, m := range items {
		built, err := buildX509Certificate(m)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return DeduplicateX509Certificates(result), nil
}

// Multi-valued to map conversions

func emailsToMaps(emails []model.ScimUserEmail) []map[string]any {
	if emails == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(emails))
	for _, e := range emails {
		m := make(map[string]any)
		if e.Value != "" {
			m["value"] = e.Value
		}
		if e.Type != "" {
			m["type"] = e.Type
		}
		if e.Display != "" {
			m["display"] = e.Display
		}
		m["primary"] = e.PrimaryFlag
		result = append(result, m)
	}
	return result
}

func phoneNumbersToMaps(phones []model.ScimUserPhoneNumber) []map[string]any {
	if phones == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(phones))
	for _, p := range phones {
		m := make(map[string]any)
		if p.Value != "" {
			m["value"] = p.Value
		}
		if p.Type != "" {
			m["type"] = p.Type
		}
		if p.Display != "" {
			m["display"] = p.Display
		}
		m["primary"] = p.PrimaryFlag
		result = append(result, m)
	}
	return result
}

func imsToMaps(ims []model.ScimUserIm) []map[string]any {
	if ims == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(ims))
	for _, im := range ims {
		m := make(map[string]any)
		if im.Value != "" {
			m["value"] = im.Value
		}
		if im.Type != "" {
			m["type"] = im.Type
		}
		if im.Display != "" {
			m["display"] = im.Display
		}
		m["primary"] = im.PrimaryFlag
		result = append(result, m)
	}
	return result
}

func photosToMaps(photos []model.ScimUserPhoto) []map[string]any {
	if photos == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(photos))
	for _, p := range photos {
		m := make(map[string]any)
		if p.Value != "" {
			m["value"] = p.Value
		}
		if p.Type != "" {
			m["type"] = p.Type
		}
		if p.Display != "" {
			m["display"] = p.Display
		}
		m["primary"] = p.PrimaryFlag
		result = append(result, m)
	}
	return result
}

func addressesToMaps(addresses []model.ScimUserAddress) []map[string]any {
	if addresses == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(addresses))
	for _, a := range addresses {
		m := make(map[string]any)
		if a.Formatted != "" {
			m["formatted"] = a.Formatted
		}
		if a.StreetAddress != "" {
			m["streetAddress"] = a.StreetAddress
		}
		if a.Locality != "" {
			m["locality"] = a.Locality
		}
		if a.Region != "" {
			m["region"] = a.Region
		}
		if a.PostalCode != "" {
			m["postalCode"] = a.PostalCode
		}
		if a.Country != "" {
			m["country"] = a.Country
		}
		if a.Type != "" {
			m["type"] = a.Type
		}
		m["primary"] = a.PrimaryFlag
		result = append(result, m)
	}
	return result
}

func entitlementsToMaps(entitlements []model.ScimUserEntitlement) []map[string]any {
	if entitlements == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(entitlements))
	for _, e := range entitlements {
		m := make(map[string]any)
		if e.Value != "" {
			m["value"] = e.Value
		}
		if e.Type != "" {
			m["type"] = e.Type
		}
		if e.Display != "" {
			m["display"] = e.Display
		}
		m["primary"] = e.PrimaryFlag
		result = append(result, m)
	}
	return result
}

func rolesToMaps(roles []model.ScimUserRole) []map[string]any {
	if roles == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		m := make(map[string]any)
		if r.Value != "" {
			m["value"] = r.Value
		}
		if r.Type != "" {
			m["type"] = r.Type
		}
		if r.Display != "" {
			m["display"] = r.Display
		}
		m["primary"] = r.PrimaryFlag
		result = append(result, m)
	}
	return result
}

func x509CertificatesToMaps(certs []model.ScimUserX509Certificate) []map[string]any {
	if certs == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		m := make(map[string]any)
		if c.Value != "" {
			m["value"] = c.Value
		}
		if c.Type != "" {
			m["type"] = c.Type
		}
		if c.Display != "" {
			m["display"] = c.Display
		}
		m["primary"] = c.PrimaryFlag
		result = append(result, m)
	}
	return result
}

// Group mapper

func GroupToScimResponse(group *model.ScimGroup, baseURL string) map[string]any {
	result := make(map[string]any)
	result["schemas"] = []string{GroupSchemaURN}
	result["id"] = group.ID.String()

	if group.ExternalID != nil {
		result["externalId"] = *group.ExternalID
	}
	result["displayName"] = group.DisplayName

	if len(group.Members) > 0 {
		members := make([]map[string]any, 0, len(group.Members))
		for _, m := range group.Members {
			members = append(members, memberToMap(m, baseURL))
		}
		result["members"] = members
	}

	result["meta"] = map[string]any{
		"resourceType": "Group",
		"created":      group.CreatedAt.UTC().Format(time.RFC3339),
		"lastModified": group.LastModified.UTC().Format(time.RFC3339),
		"location":     baseURL + "/Groups/" + group.ID.String(),
		"version":      fmt.Sprintf("W/\"%d\"", group.Version),
	}

	return result
}

func memberToMap(m model.ScimGroupMembership, baseURL string) map[string]any {
	result := make(map[string]any)
	result["value"] = m.MemberValue.String()

	refType := "Users"
	memberType := "User"
	if m.MemberType != nil && *m.MemberType == "Group" {
		refType = "Groups"
		memberType = "Group"
	}
	result["$ref"] = baseURL + "/" + refType + "/" + m.MemberValue.String()
	if m.Display != nil {
		result["display"] = *m.Display
	}
	result["type"] = memberType

	return result
}

// MS compat mapper

func ApplyMsCompat(response map[string]any) map[string]any {
	convertPrimaryToString(response, "entitlements")
	convertPrimaryToString(response, "roles")
	convertPrimaryToString(response, "x509Certificates")
	addManagerAlias(response)
	return response
}

func convertPrimaryToString(response map[string]any, key string) {
	items, ok := response[key].([]map[string]any)
	if !ok {
		return
	}
	for _, item := range items {
		if primary, ok := item["primary"]; ok {
			switch v := primary.(type) {
			case bool:
				if v {
					item["primary"] = "true"
				} else {
					item["primary"] = "false"
				}
			}
		}
	}
}

func addManagerAlias(response map[string]any) {
	ext, ok := response[EnterpriseSchemaURN].(map[string]any)
	if !ok {
		return
	}
	mgr, ok := ext["manager"].(map[string]any)
	if !ok {
		return
	}
	if v, ok := mgr["value"]; ok {
		response[EnterpriseSchemaURN+":manager"] = v
	}
}

// Helper for generating group references for a user

func BuildUserGroupRef(groupID uuid.UUID, displayName, baseURL string) map[string]any {
	return map[string]any{
		"value":   groupID.String(),
		"$ref":    baseURL + "/Groups/" + groupID.String(),
		"display": displayName,
		"type":    "direct",
	}
}
