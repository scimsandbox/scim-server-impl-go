package scim

import (
	"fmt"
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

func ApplyFromScimInput(user *model.ScimUser, input map[string]any) {
	applySimpleAttributes(user, input)
	applyNameAttribute(user, input)

	if v, ok := input["emails"]; ok {
		user.Emails = replaceCollectionEmails(v)
	}
	if v, ok := input["phoneNumbers"]; ok {
		user.PhoneNumbers = replaceCollectionPhoneNumbers(v)
	}
	if v, ok := input["addresses"]; ok {
		user.Addresses = replaceCollectionAddresses(v)
	}
	if v, ok := input["ims"]; ok {
		user.Ims = replaceCollectionIms(v)
	}
	if v, ok := input["photos"]; ok {
		user.Photos = replaceCollectionPhotos(v)
	}
	if v, ok := input["entitlements"]; ok {
		user.Entitlements = replaceCollectionEntitlements(v)
	}
	if v, ok := input["roles"]; ok {
		user.Roles = replaceCollectionRoles(v)
	}
	if v, ok := input["x509Certificates"]; ok {
		user.X509Certificates = replaceCollectionX509Certificates(v)
	}

	applyEnterpriseExtension(user, input)
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

func applySimpleAttributes(user *model.ScimUser, input map[string]any) {
	if v, ok := input["userName"].(string); ok {
		user.UserName = v
	}
	if v, ok := input["externalId"]; ok {
		user.ExternalID = toStringPtr(v)
	}
	if v, ok := input["displayName"]; ok {
		user.DisplayName = toStringPtr(v)
	}
	if v, ok := input["nickName"]; ok {
		user.NickName = toStringPtr(v)
	}
	if v, ok := input["profileUrl"]; ok {
		user.ProfileUrl = toStringPtr(v)
	}
	if v, ok := input["title"]; ok {
		user.Title = toStringPtr(v)
	}
	if v, ok := input["userType"]; ok {
		user.UserType = toStringPtr(v)
	}
	if v, ok := input["preferredLanguage"]; ok {
		user.PreferredLanguage = toStringPtr(v)
	}
	if v, ok := input["locale"]; ok {
		user.Locale = toStringPtr(v)
	}
	if v, ok := input["timezone"]; ok {
		user.Timezone = toStringPtr(v)
	}
	if v, ok := input["active"]; ok {
		user.Active = toBool(v)
	} else {
		user.Active = true
	}
	if v, ok := input["password"]; ok {
		user.Password = toStringPtr(v)
	}
}

func applyNameAttribute(user *model.ScimUser, input map[string]any) {
	nameRaw, ok := input["name"]
	if !ok {
		return
	}
	nameMap, ok := nameRaw.(map[string]any)
	if !ok {
		return
	}
	if v, ok := nameMap["formatted"]; ok {
		user.NameFormatted = toStringPtr(v)
	}
	if v, ok := nameMap["familyName"]; ok {
		user.NameFamilyName = toStringPtr(v)
	}
	if v, ok := nameMap["givenName"]; ok {
		user.NameGivenName = toStringPtr(v)
	}
	if v, ok := nameMap["middleName"]; ok {
		user.NameMiddleName = toStringPtr(v)
	}
	if v, ok := nameMap["honorificPrefix"]; ok {
		user.NameHonorificPrefix = toStringPtr(v)
	}
	if v, ok := nameMap["honorificSuffix"]; ok {
		user.NameHonorificSuffix = toStringPtr(v)
	}
}

func applyEnterpriseExtension(user *model.ScimUser, input map[string]any) {
	extRaw, ok := input[EnterpriseSchemaURN]
	if !ok {
		return
	}
	ext, ok := extRaw.(map[string]any)
	if !ok {
		return
	}
	if v, ok := ext["employeeNumber"]; ok {
		user.EnterpriseEmployeeNumber = toStringPtr(v)
	}
	if v, ok := ext["costCenter"]; ok {
		user.EnterpriseCostCenter = toStringPtr(v)
	}
	if v, ok := ext["organization"]; ok {
		user.EnterpriseOrganization = toStringPtr(v)
	}
	if v, ok := ext["division"]; ok {
		user.EnterpriseDivision = toStringPtr(v)
	}
	if v, ok := ext["department"]; ok {
		user.EnterpriseDepartment = toStringPtr(v)
	}
	if mgrRaw, ok := ext["manager"]; ok {
		applyEnterpriseManager(user, mgrRaw)
	}
}

func applyEnterpriseManager(user *model.ScimUser, mgrRaw any) {
	if mgrRaw == nil {
		user.EnterpriseManagerValue = nil
		user.EnterpriseManagerRef = nil
		user.EnterpriseManagerDisplay = nil
		return
	}
	switch mgr := mgrRaw.(type) {
	case string:
		user.EnterpriseManagerValue = &mgr
	case map[string]any:
		if v, ok := mgr["value"]; ok {
			user.EnterpriseManagerValue = toStringPtr(v)
		}
		if v, ok := mgr["$ref"]; ok {
			user.EnterpriseManagerRef = toStringPtr(v)
		}
		if v, ok := mgr["displayName"]; ok {
			user.EnterpriseManagerDisplay = toStringPtr(v)
		}
	}
}

// Collection replace helpers

func replaceCollectionEmails(v any) []model.ScimUserEmail {
	items := toAnySlice(v)
	result := make([]model.ScimUserEmail, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildEmail(m))
		}
	}
	return result
}

func replaceCollectionPhoneNumbers(v any) []model.ScimUserPhoneNumber {
	items := toAnySlice(v)
	result := make([]model.ScimUserPhoneNumber, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildPhoneNumber(m))
		}
	}
	return result
}

func replaceCollectionAddresses(v any) []model.ScimUserAddress {
	items := toAnySlice(v)
	result := make([]model.ScimUserAddress, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildAddress(m))
		}
	}
	return result
}

func replaceCollectionIms(v any) []model.ScimUserIm {
	items := toAnySlice(v)
	result := make([]model.ScimUserIm, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildIm(m))
		}
	}
	return result
}

func replaceCollectionPhotos(v any) []model.ScimUserPhoto {
	items := toAnySlice(v)
	result := make([]model.ScimUserPhoto, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildPhoto(m))
		}
	}
	return result
}

func replaceCollectionEntitlements(v any) []model.ScimUserEntitlement {
	items := toAnySlice(v)
	result := make([]model.ScimUserEntitlement, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildEntitlement(m))
		}
	}
	return result
}

func replaceCollectionRoles(v any) []model.ScimUserRole {
	items := toAnySlice(v)
	result := make([]model.ScimUserRole, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildRole(m))
		}
	}
	return result
}

func replaceCollectionX509Certificates(v any) []model.ScimUserX509Certificate {
	items := toAnySlice(v)
	result := make([]model.ScimUserX509Certificate, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, buildX509Certificate(m))
		}
	}
	return result
}

func toAnySlice(v any) []any {
	if v == nil {
		return nil
	}
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
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
