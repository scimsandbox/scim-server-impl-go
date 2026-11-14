package scim

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

var readOnlyAttrs = map[string]bool{
	"id": true, "meta": true, "meta.created": true, "meta.lastmodified": true,
	"meta.location": true, "meta.resourcetype": true, "meta.version": true,
	"groups": true, "manager.displayname": true,
}

var filteredPathRegex = regexp.MustCompile(`^(\w+)\[(.+)\](?:\.(\w+))?$`)

var multiValuedAttrs = map[string]bool{
	"emails": true, "phonenumbers": true, "addresses": true, "ims": true,
	"photos": true, "entitlements": true, "roles": true, "x509certificates": true,
}

var emailTypes = map[string]bool{"work": true, "home": true, "other": true}
var phoneTypes = map[string]bool{"work": true, "home": true, "mobile": true, "fax": true, "pager": true, "other": true}
var imTypes = map[string]bool{"aim": true, "gtalk": true, "icq": true, "xmpp": true, "skype": true, "qq": true, "msn": true, "yahoo": true}
var photoTypes = map[string]bool{"photo": true, "thumbnail": true}
var addressTypes = map[string]bool{"work": true, "home": true, "other": true}

const (
	enterpriseSchemaURN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

func ApplyPatchOperations(user *model.ScimUser, operations []map[string]any) error {
	if len(operations) == 0 {
		return NewScimError(400, "invalidValue", "PATCH operations required")
	}
	for _, op := range operations {
		rawOp, _ := op["op"].(string)
		if rawOp == "" {
			return NewScimError(400, "invalidValue", "PATCH op is required")
		}
		opType := strings.ToLower(rawOp)
		path, _ := op["path"].(string)
		value := op["value"]

		path = stripPatchURNPrefix(path)

		if path != "" && readOnlyAttrs[strings.ToLower(path)] {
			return NewScimError(400, "mutability", "Attribute '"+path+"' is read-only")
		}

		switch opType {
		case "add":
			if value == nil {
				return NewScimError(400, "invalidValue", "PATCH add operation must contain a 'value' member")
			}
			if err := applyAdd(user, path, value); err != nil {
				return err
			}
		case "replace":
			if err := applyReplace(user, path, value); err != nil {
				return err
			}
		case "remove":
			if err := applyRemove(user, path, value); err != nil {
				return err
			}
		default:
			return NewScimError(400, "invalidValue", "Unsupported PATCH op: "+opType)
		}
	}
	return nil
}

func stripPatchURNPrefix(path string) string {
	if path == "" {
		return path
	}
	lower := strings.ToLower(path)
	coreUser := strings.ToLower("urn:ietf:params:scim:schemas:core:2.0:User:")
	if strings.HasPrefix(lower, coreUser) {
		return path[len(coreUser):]
	}
	entUser := strings.ToLower(enterpriseSchemaURN + ":")
	if strings.HasPrefix(lower, entUser) {
		return path[len(entUser):]
	}
	if strings.EqualFold(path, enterpriseSchemaURN) {
		return enterpriseSchemaURN
	}
	return path
}

func applyAdd(user *model.ScimUser, path string, value any) error {
	if path == "" {
		return applyValueMap(user, value, false)
	}
	m := filteredPathRegex.FindStringSubmatch(path)
	if m != nil {
		return applyFilteredAdd(user, m[1], m[2], m[3], value)
	}
	lower := strings.ToLower(path)
	if lower == "name" {
		return setNameAttribute(user, value)
	}
	if strings.EqualFold(path, enterpriseSchemaURN) || strings.HasPrefix(lower, strings.ToLower(enterpriseSchemaURN)+":") || isEnterpriseAttr(path) {
		return setEnterpriseAttribute(user, path, value)
	}
	if strings.Contains(path, ".") {
		return setSubAttribute(user, path, value)
	}
	if multiValuedAttrs[lower] {
		return addToMultiValued(user, lower, value)
	}
	return setSingleAttribute(user, path, value)
}

func applyReplace(user *model.ScimUser, path string, value any) error {
	if path == "" {
		return applyValueMap(user, value, true)
	}
	m := filteredPathRegex.FindStringSubmatch(path)
	if m != nil {
		return applyFilteredReplace(user, m[1], m[2], m[3], value)
	}
	lower := strings.ToLower(path)
	if lower == "name" {
		return setNameAttribute(user, value)
	}
	if strings.EqualFold(path, enterpriseSchemaURN) || strings.HasPrefix(lower, strings.ToLower(enterpriseSchemaURN)+":") || isEnterpriseAttr(path) {
		return setEnterpriseAttribute(user, path, value)
	}
	if strings.Contains(path, ".") {
		return setSubAttribute(user, path, value)
	}
	if multiValuedAttrs[lower] {
		return replaceMultiValued(user, lower, value)
	}
	return setSingleAttribute(user, path, value)
}

func applyRemove(user *model.ScimUser, path string, _ any) error {
	if path == "" {
		return NewScimError(400, "noTarget", "PATCH remove requires a path")
	}
	m := filteredPathRegex.FindStringSubmatch(path)
	if m != nil {
		return applyFilteredRemove(user, m[1], m[2])
	}
	lower := strings.ToLower(path)
	if lower == "name" {
		return setNameAttribute(user, nil)
	}
	if strings.EqualFold(path, enterpriseSchemaURN) || strings.HasPrefix(lower, strings.ToLower(enterpriseSchemaURN)+":") || isEnterpriseAttr(path) {
		return clearEnterpriseAttribute(user, path)
	}
	if strings.Contains(path, ".") {
		return setSubAttribute(user, path, nil)
	}
	return clearAttribute(user, lower)
}

func isEnterpriseAttr(path string) bool {
	lower := strings.ToLower(path)
	switch {
	case lower == "employeenumber", lower == "costcenter", lower == "organization",
		lower == "division", lower == "department", lower == "manager":
		return true
	case strings.HasPrefix(lower, "manager."):
		return true
	}
	return false
}

func setSingleAttribute(user *model.ScimUser, path string, value any) error {
	lower := strings.ToLower(path)
	if readOnlyAttrs[lower] || strings.HasPrefix(lower, "meta.") {
		return NewScimError(400, "mutability", "Attribute '"+path+"' is read-only")
	}
	switch lower {
	case "username":
		s, err := parseStrictStringPtr(value, "userName")
		if err != nil {
			return err
		}
		if s == nil {
			return NewScimError(400, "invalidValue", "userName cannot be null")
		}
		// userName is REQUIRED (RFC 7643 §4.1). Guarding here rather than in the
		// handlers keeps direct PATCH and bulk PATCH from drifting apart: add,
		// replace and pathless value-map operations all funnel through this call.
		if *s == "" {
			return NewScimError(400, "invalidValue", "userName is required")
		}
		user.UserName = *s
	case "externalid":
		s, err := parseStrictStringPtr(value, "externalId")
		if err != nil {
			return err
		}
		user.ExternalID = s
	case "displayname":
		s, err := parseStrictStringPtr(value, "displayName")
		if err != nil {
			return err
		}
		user.DisplayName = s
	case "nickname":
		s, err := parseStrictStringPtr(value, "nickName")
		if err != nil {
			return err
		}
		user.NickName = s
	case "profileurl":
		s, err := parseStrictStringPtr(value, "profileUrl")
		if err != nil {
			return err
		}
		if s != nil && *s != "" {
			if err := validateReference(*s); err != nil {
				return err
			}
		}
		user.ProfileUrl = s
	case "title":
		s, err := parseStrictStringPtr(value, "title")
		if err != nil {
			return err
		}
		user.Title = s
	case "usertype":
		s, err := parseStrictStringPtr(value, "userType")
		if err != nil {
			return err
		}
		user.UserType = s
	case "preferredlanguage":
		s, err := parseStrictStringPtr(value, "preferredLanguage")
		if err != nil {
			return err
		}
		user.PreferredLanguage = s
	case "locale":
		s, err := parseStrictStringPtr(value, "locale")
		if err != nil {
			return err
		}
		user.Locale = s
	case "timezone":
		s, err := parseStrictStringPtr(value, "timezone")
		if err != nil {
			return err
		}
		user.Timezone = s
	case "active":
		b, err := parseStrictBool(value, "active")
		if err != nil {
			return err
		}
		user.Active = b
	case "password":
		rawPw, err := parsePasswordValue(value)
		if err != nil {
			return err
		}
		if user.Password != nil && rawPw != nil && *rawPw != "" && bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(*rawPw)) == nil {
			return nil
		}
		pw, err := HashPassword(rawPw)
		if err != nil {
			return err
		}
		user.Password = pw
	default:
		return NewScimError(400, "invalidPath", "Unknown attribute: "+path)
	}
	return nil
}

func setSubAttribute(user *model.ScimUser, path string, value any) error {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) != 2 {
		return NewScimError(400, "invalidPath", "Invalid sub-attribute path: "+path)
	}
	parent := strings.ToLower(parts[0])
	sub := strings.ToLower(parts[1])

	if parent == "meta" {
		return NewScimError(400, "mutability", "Attribute '"+path+"' is read-only")
	}
	if parent != "name" {
		return NewScimError(400, "invalidPath", "Unknown complex attribute: "+parts[0])
	}

	s, err := parseStrictStringPtr(value, path)
	if err != nil {
		return err
	}
	switch sub {
	case "formatted":
		user.NameFormatted = s
	case "familyname":
		user.NameFamilyName = s
	case "givenname":
		user.NameGivenName = s
	case "middlename":
		user.NameMiddleName = s
	case "honorificprefix":
		user.NameHonorificPrefix = s
	case "honorificsuffix":
		user.NameHonorificSuffix = s
	default:
		return NewScimError(400, "invalidPath", "Unknown name sub-attribute: "+parts[1])
	}
	return nil
}

func setNameAttribute(user *model.ScimUser, value any) error {
	if value == nil {
		user.NameFormatted = nil
		user.NameFamilyName = nil
		user.NameGivenName = nil
		user.NameMiddleName = nil
		user.NameHonorificPrefix = nil
		user.NameHonorificSuffix = nil
		return nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return NewScimError(400, "invalidValue", "Attribute 'name' must be an object")
	}
	for subAttr, subVal := range m {
		s, err := parseStrictStringPtr(subVal, "name."+subAttr)
		if err != nil {
			return err
		}
		switch strings.ToLower(subAttr) {
		case "formatted":
			user.NameFormatted = s
		case "familyname":
			user.NameFamilyName = s
		case "givenname":
			user.NameGivenName = s
		case "middlename":
			user.NameMiddleName = s
		case "honorificprefix":
			user.NameHonorificPrefix = s
		case "honorificsuffix":
			user.NameHonorificSuffix = s
		default:
			return NewScimError(400, "invalidPath", "Unknown name sub-attribute: "+subAttr)
		}
	}
	return nil
}

func setEnterpriseAttribute(user *model.ScimUser, path string, value any) error {
	attr := path
	lowerPath := strings.ToLower(path)
	lowerEnt := strings.ToLower(enterpriseSchemaURN)
	if strings.HasPrefix(lowerPath, lowerEnt+":") {
		attr = path[len(enterpriseSchemaURN)+1:]
	} else if lowerPath == lowerEnt {
		return applyEnterpriseValueMap(user, value)
	}

	switch strings.ToLower(attr) {
	case "employeenumber":
		s, err := parseStrictStringPtr(value, "employeeNumber")
		if err != nil {
			return err
		}
		user.EnterpriseEmployeeNumber = s
	case "costcenter":
		s, err := parseStrictStringPtr(value, "costCenter")
		if err != nil {
			return err
		}
		user.EnterpriseCostCenter = s
	case "organization":
		s, err := parseStrictStringPtr(value, "organization")
		if err != nil {
			return err
		}
		user.EnterpriseOrganization = s
	case "division":
		s, err := parseStrictStringPtr(value, "division")
		if err != nil {
			return err
		}
		user.EnterpriseDivision = s
	case "department":
		s, err := parseStrictStringPtr(value, "department")
		if err != nil {
			return err
		}
		user.EnterpriseDepartment = s
	case "manager":
		return setEnterpriseManager(user, value)
	case "manager.value":
		s, err := parseStrictStringPtr(value, "manager.value")
		if err != nil {
			return err
		}
		user.EnterpriseManagerValue = s
		user.EnterpriseManagerDisplay = nil
	case "manager.$ref":
		s, err := parseStrictStringPtr(value, "manager.$ref")
		if err != nil {
			return err
		}
		user.EnterpriseManagerRef = s
		if s != nil && strings.TrimSpace(*s) != "" {
			if refUUID := ExtractUUIDFromRef(*s); refUUID != "" {
				user.EnterpriseManagerValue = &refUUID
				user.EnterpriseManagerDisplay = nil
			}
		}
	case "manager.displayname":
		return NewScimError(400, "mutability", "Attribute 'manager.displayName' is readOnly and cannot be modified")
	default:
		return NewScimError(400, "invalidPath", "Unknown enterprise attribute: "+attr)
	}
	return nil
}

func setEnterpriseManager(user *model.ScimUser, value any) error {
	if value == nil {
		user.EnterpriseManagerValue = nil
		user.EnterpriseManagerRef = nil
		user.EnterpriseManagerDisplay = nil
		return nil
	}
	switch v := value.(type) {
	case string:
		normStr := NormalizeNFC(v)
		user.EnterpriseManagerValue = &normStr
		user.EnterpriseManagerDisplay = nil
	case map[string]any:
		var parsedVal *string
		valProvided := false
		if val, ok := v["value"]; ok {
			valProvided = true
			s, err := parseStrictStringPtr(val, "manager.value")
			if err != nil {
				return err
			}
			parsedVal = s
			user.EnterpriseManagerValue = s
		}
		if ref, ok := v["$ref"]; ok {
			s, err := parseStrictStringPtr(ref, "manager.$ref")
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
				} else if refUUID != "" && (!valProvided || parsedVal == nil || strings.TrimSpace(*parsedVal) == "") {
					user.EnterpriseManagerValue = &refUUID
				}
			}
		}
		// RFC 7643 §4.3: manager.displayName is readOnly; ignore client-supplied values in manager object.
		user.EnterpriseManagerDisplay = nil
	default:
		return NewScimError(400, "invalidValue", "Attribute 'manager' must be an object or string")
	}
	return nil
}

func applyEnterpriseValueMap(user *model.ScimUser, value any) error {
	if value == nil {
		user.EnterpriseEmployeeNumber = nil
		user.EnterpriseCostCenter = nil
		user.EnterpriseOrganization = nil
		user.EnterpriseDivision = nil
		user.EnterpriseDepartment = nil
		user.EnterpriseManagerValue = nil
		user.EnterpriseManagerRef = nil
		user.EnterpriseManagerDisplay = nil
		return nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return NewScimError(400, "invalidValue", "Enterprise extension value must be an object")
	}
	for k, v := range m {
		if err := setEnterpriseAttribute(user, k, v); err != nil {
			return err
		}
	}
	return nil
}

func clearEnterpriseAttribute(user *model.ScimUser, path string) error {
	attr := path
	lowerPath := strings.ToLower(path)
	lowerEnt := strings.ToLower(enterpriseSchemaURN)
	if strings.HasPrefix(lowerPath, lowerEnt+":") {
		attr = path[len(enterpriseSchemaURN)+1:]
	} else if lowerPath == lowerEnt {
		user.EnterpriseEmployeeNumber = nil
		user.EnterpriseCostCenter = nil
		user.EnterpriseOrganization = nil
		user.EnterpriseDivision = nil
		user.EnterpriseDepartment = nil
		user.EnterpriseManagerValue = nil
		user.EnterpriseManagerRef = nil
		user.EnterpriseManagerDisplay = nil
		return nil
	}
	return setEnterpriseAttribute(user, attr, nil)
}

func applyValueMap(user *model.ScimUser, value any, isReplace bool) error {
	m, ok := value.(map[string]any)
	if !ok {
		return NewScimError(400, "invalidValue", "PATCH add/replace without path requires a value object")
	}
	for k, v := range m {
		key := stripPatchURNPrefix(k)
		lower := strings.ToLower(key)
		if readOnlyAttrs[lower] || strings.HasPrefix(lower, "meta.") {
			return NewScimError(400, "mutability", "Attribute '"+k+"' is read-only")
		}
		if lower == "name" {
			if err := setNameAttribute(user, v); err != nil {
				return err
			}
		} else if strings.EqualFold(key, enterpriseSchemaURN) || strings.HasPrefix(lower, strings.ToLower(enterpriseSchemaURN)+":") || isEnterpriseAttr(key) {
			if err := setEnterpriseAttribute(user, key, v); err != nil {
				return err
			}
		} else if strings.Contains(key, ".") {
			if err := setSubAttribute(user, key, v); err != nil {
				return err
			}
		} else if multiValuedAttrs[lower] {
			if isReplace {
				if err := replaceMultiValued(user, lower, v); err != nil {
					return err
				}
			} else {
				if err := addToMultiValued(user, lower, v); err != nil {
					return err
				}
			}
		} else {
			if err := setSingleAttribute(user, key, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func addToMultiValued(user *model.ScimUser, attr string, value any) error {
	items, err := toItemList(value)
	if err != nil {
		return err
	}
	if err := ValidateSinglePrimary(items); err != nil {
		return err
	}
	switch attr {
	case "emails":
		for _, item := range items {
			built, err := buildEmail(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.Emails {
					user.Emails[i].PrimaryFlag = false
				}
			}
			user.Emails = append(user.Emails, built)
		}
		user.Emails = DeduplicateEmails(user.Emails)
	case "phonenumbers":
		for _, item := range items {
			built, err := buildPhoneNumber(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.PhoneNumbers {
					user.PhoneNumbers[i].PrimaryFlag = false
				}
			}
			user.PhoneNumbers = append(user.PhoneNumbers, built)
		}
		user.PhoneNumbers = DeduplicatePhoneNumbers(user.PhoneNumbers)
	case "addresses":
		for _, item := range items {
			built, err := buildAddress(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.Addresses {
					user.Addresses[i].PrimaryFlag = false
				}
			}
			user.Addresses = append(user.Addresses, built)
		}
		user.Addresses = DeduplicateAddresses(user.Addresses)
	case "ims":
		for _, item := range items {
			built, err := buildIm(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.Ims {
					user.Ims[i].PrimaryFlag = false
				}
			}
			user.Ims = append(user.Ims, built)
		}
		user.Ims = DeduplicateIms(user.Ims)
	case "photos":
		for _, item := range items {
			built, err := buildPhoto(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.Photos {
					user.Photos[i].PrimaryFlag = false
				}
			}
			user.Photos = append(user.Photos, built)
		}
		user.Photos = DeduplicatePhotos(user.Photos)
	case "entitlements":
		for _, item := range items {
			built, err := buildEntitlement(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.Entitlements {
					user.Entitlements[i].PrimaryFlag = false
				}
			}
			user.Entitlements = append(user.Entitlements, built)
		}
		user.Entitlements = DeduplicateEntitlements(user.Entitlements)
	case "roles":
		for _, item := range items {
			built, err := buildRole(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.Roles {
					user.Roles[i].PrimaryFlag = false
				}
			}
			user.Roles = append(user.Roles, built)
		}
		user.Roles = DeduplicateRoles(user.Roles)
	case "x509certificates":
		for _, item := range items {
			built, err := buildX509Certificate(item)
			if err != nil {
				return err
			}
			if built.PrimaryFlag {
				for i := range user.X509Certificates {
					user.X509Certificates[i].PrimaryFlag = false
				}
			}
			user.X509Certificates = append(user.X509Certificates, built)
		}
		user.X509Certificates = DeduplicateX509Certificates(user.X509Certificates)
	}
	return nil
}

func replaceMultiValued(user *model.ScimUser, attr string, value any) error {
	if err := clearAttribute(user, attr); err != nil {
		return err
	}
	if value == nil {
		return nil
	}
	return addToMultiValued(user, attr, value)
}

// DeduplicateEmails deduplicates identical (type, value) email pairs (USR_22 / RFC 7643 §2.4).
// Comparison is case-insensitive and whitespace-trimmed on both Type and Value.
// The first occurrence's raw value and display are preserved; if any duplicate has PrimaryFlag=true,
// the retained entry's PrimaryFlag is set to true.
func DeduplicateEmails(emails []model.ScimUserEmail) []model.ScimUserEmail {
	if len(emails) <= 1 {
		return emails
	}
	result := make([]model.ScimUserEmail, 0, len(emails))
	seen := make(map[string]int)
	for _, email := range emails {
		key := strings.ToLower(strings.TrimSpace(email.Type)) + "\x00" + strings.ToLower(strings.TrimSpace(email.Value))
		if idx, found := seen[key]; found {
			if email.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, email)
	}
	return result
}

func DeduplicatePhoneNumbers(phones []model.ScimUserPhoneNumber) []model.ScimUserPhoneNumber {
	if len(phones) <= 1 {
		return phones
	}
	result := make([]model.ScimUserPhoneNumber, 0, len(phones))
	seen := make(map[string]int)
	for _, p := range phones {
		key := strings.ToLower(strings.TrimSpace(p.Type)) + "\x00" + strings.ToLower(strings.TrimSpace(p.Value))
		if idx, found := seen[key]; found {
			if p.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, p)
	}
	return result
}

func DeduplicateIms(ims []model.ScimUserIm) []model.ScimUserIm {
	if len(ims) <= 1 {
		return ims
	}
	result := make([]model.ScimUserIm, 0, len(ims))
	seen := make(map[string]int)
	for _, im := range ims {
		key := strings.ToLower(strings.TrimSpace(im.Type)) + "\x00" + strings.ToLower(strings.TrimSpace(im.Value))
		if idx, found := seen[key]; found {
			if im.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, im)
	}
	return result
}

func DeduplicatePhotos(photos []model.ScimUserPhoto) []model.ScimUserPhoto {
	if len(photos) <= 1 {
		return photos
	}
	result := make([]model.ScimUserPhoto, 0, len(photos))
	seen := make(map[string]int)
	for _, p := range photos {
		key := strings.ToLower(strings.TrimSpace(p.Type)) + "\x00" + strings.TrimSpace(p.Value)
		if idx, found := seen[key]; found {
			if p.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, p)
	}
	return result
}

func DeduplicateEntitlements(ents []model.ScimUserEntitlement) []model.ScimUserEntitlement {
	if len(ents) <= 1 {
		return ents
	}
	result := make([]model.ScimUserEntitlement, 0, len(ents))
	seen := make(map[string]int)
	for _, e := range ents {
		key := strings.ToLower(strings.TrimSpace(e.Type)) + "\x00" + strings.ToLower(strings.TrimSpace(e.Value))
		if idx, found := seen[key]; found {
			if e.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, e)
	}
	return result
}

func DeduplicateRoles(roles []model.ScimUserRole) []model.ScimUserRole {
	if len(roles) <= 1 {
		return roles
	}
	result := make([]model.ScimUserRole, 0, len(roles))
	seen := make(map[string]int)
	for _, r := range roles {
		key := strings.ToLower(strings.TrimSpace(r.Type)) + "\x00" + strings.ToLower(strings.TrimSpace(r.Value))
		if idx, found := seen[key]; found {
			if r.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, r)
	}
	return result
}

func DeduplicateX509Certificates(certs []model.ScimUserX509Certificate) []model.ScimUserX509Certificate {
	if len(certs) <= 1 {
		return certs
	}
	result := make([]model.ScimUserX509Certificate, 0, len(certs))
	seen := make(map[string]int)
	for _, c := range certs {
		key := strings.ToLower(strings.TrimSpace(c.Type)) + "\x00" + strings.TrimSpace(c.Value)
		if idx, found := seen[key]; found {
			if c.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, c)
	}
	return result
}

func DeduplicateAddresses(addrs []model.ScimUserAddress) []model.ScimUserAddress {
	if len(addrs) <= 1 {
		return addrs
	}
	result := make([]model.ScimUserAddress, 0, len(addrs))
	seen := make(map[string]int)
	for _, a := range addrs {
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(a.Type)),
			strings.ToLower(strings.TrimSpace(a.Formatted)),
			strings.ToLower(strings.TrimSpace(a.StreetAddress)),
			strings.ToLower(strings.TrimSpace(a.Locality)),
			strings.ToLower(strings.TrimSpace(a.Region)),
			strings.ToLower(strings.TrimSpace(a.PostalCode)),
			strings.ToLower(strings.TrimSpace(a.Country)),
		}, "\x00")
		if idx, found := seen[key]; found {
			if a.PrimaryFlag {
				result[idx].PrimaryFlag = true
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, a)
	}
	return result
}

func clearAttribute(user *model.ScimUser, attr string) error {
	switch strings.ToLower(attr) {
	case "username":
		return NewScimError(400, "mutability", "Required attribute 'userName' cannot be removed")
	case "id", "meta", "groups":
		return NewScimError(400, "mutability", "Attribute '"+attr+"' is read-only and cannot be removed")
	case "name":
		return setNameAttribute(user, nil)
	case "externalid":
		user.ExternalID = nil
	case "displayname":
		user.DisplayName = nil
	case "nickname":
		user.NickName = nil
	case "profileurl":
		user.ProfileUrl = nil
	case "title":
		user.Title = nil
	case "usertype":
		user.UserType = nil
	case "preferredlanguage":
		user.PreferredLanguage = nil
	case "locale":
		user.Locale = nil
	case "timezone":
		user.Timezone = nil
	case "active":
		user.Active = false
	case "password":
		user.Password = nil
	case "emails":
		user.Emails = nil
	case "phonenumbers":
		user.PhoneNumbers = nil
	case "addresses":
		user.Addresses = nil
	case "ims":
		user.Ims = nil
	case "photos":
		user.Photos = nil
	case "entitlements":
		user.Entitlements = nil
	case "roles":
		user.Roles = nil
	case "x509certificates":
		user.X509Certificates = nil
	default:
		return NewScimError(400, "invalidPath", "Cannot remove attribute: "+attr)
	}
	return nil
}

// Filtered operations

func applyFilteredAdd(user *model.ScimUser, collection, filterExpr, subAttr string, value any) error {
	lower := strings.ToLower(collection)
	if subAttr == "" {
		return addToMultiValued(user, lower, value)
	}
	return applyFilteredUpdate(user, lower, filterExpr, subAttr, value)
}

func applyFilteredReplace(user *model.ScimUser, collection, filterExpr, subAttr string, value any) error {
	lower := strings.ToLower(collection)
	return applyFilteredUpdate(user, lower, filterExpr, subAttr, value)
}

func applyFilteredRemove(user *model.ScimUser, collection, filterExpr string) error {
	lower := strings.ToLower(collection)
	switch lower {
	case "emails":
		user.Emails = removeMatching(user.Emails, filterExpr, matchesEmailFilter)
	case "phonenumbers":
		user.PhoneNumbers = removeMatching(user.PhoneNumbers, filterExpr, matchesPhoneFilter)
	case "addresses":
		user.Addresses = removeMatching(user.Addresses, filterExpr, matchesAddressFilter)
	case "ims":
		user.Ims = removeMatching(user.Ims, filterExpr, matchesImFilter)
	case "photos":
		user.Photos = removeMatching(user.Photos, filterExpr, matchesPhotoFilter)
	case "entitlements":
		user.Entitlements = removeMatching(user.Entitlements, filterExpr, matchesEntitlementFilter)
	case "roles":
		user.Roles = removeMatching(user.Roles, filterExpr, matchesRoleFilter)
	case "x509certificates":
		user.X509Certificates = removeMatching(user.X509Certificates, filterExpr, matchesCertFilter)
	default:
		return NewScimError(400, "invalidPath", "Unknown collection: "+collection)
	}
	return nil
}

func setsPrimaryTrue(subAttr string, value any) bool {
	if strings.EqualFold(subAttr, "primary") {
		b, ok := value.(bool)
		return ok && b
	}
	if subAttr == "" {
		if m, ok := value.(map[string]any); ok {
			for k, v := range m {
				if strings.EqualFold(k, "primary") {
					if b, ok := v.(bool); ok && b {
						return true
					}
				}
			}
		}
	}
	return false
}

func applyFilteredUpdate(user *model.ScimUser, collection, filterExpr, subAttr string, value any) error {
	fc := parseEqFilter(filterExpr)
	if fc == nil {
		return NewScimError(400, "invalidFilter", "Cannot parse filter: "+filterExpr)
	}
	found := false
	demoteOthers := setsPrimaryTrue(subAttr, value)

	switch collection {
	case "emails":
		for i := range user.Emails {
			if matchesEmailFilter(&user.Emails[i], filterExpr) {
				if err := setEmailSubAttribute(&user.Emails[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.Emails {
						if j != i {
							user.Emails[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.Emails = DeduplicateEmails(user.Emails)
		}
	case "phonenumbers":
		for i := range user.PhoneNumbers {
			if matchesPhoneFilter(&user.PhoneNumbers[i], filterExpr) {
				if err := setPhoneSubAttribute(&user.PhoneNumbers[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.PhoneNumbers {
						if j != i {
							user.PhoneNumbers[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.PhoneNumbers = DeduplicatePhoneNumbers(user.PhoneNumbers)
		}
	case "addresses":
		for i := range user.Addresses {
			if matchesAddressFilter(&user.Addresses[i], filterExpr) {
				if err := setAddressSubAttribute(&user.Addresses[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.Addresses {
						if j != i {
							user.Addresses[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.Addresses = DeduplicateAddresses(user.Addresses)
		}
	case "ims":
		for i := range user.Ims {
			if matchesImFilter(&user.Ims[i], filterExpr) {
				if err := setImSubAttribute(&user.Ims[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.Ims {
						if j != i {
							user.Ims[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.Ims = DeduplicateIms(user.Ims)
		}
	case "photos":
		for i := range user.Photos {
			if matchesPhotoFilter(&user.Photos[i], filterExpr) {
				if err := setPhotoSubAttribute(&user.Photos[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.Photos {
						if j != i {
							user.Photos[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.Photos = DeduplicatePhotos(user.Photos)
		}
	case "entitlements":
		for i := range user.Entitlements {
			if matchesEntitlementFilter(&user.Entitlements[i], filterExpr) {
				if err := setEntitlementSubAttribute(&user.Entitlements[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.Entitlements {
						if j != i {
							user.Entitlements[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.Entitlements = DeduplicateEntitlements(user.Entitlements)
		}
	case "roles":
		for i := range user.Roles {
			if matchesRoleFilter(&user.Roles[i], filterExpr) {
				if err := setRoleSubAttribute(&user.Roles[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.Roles {
						if j != i {
							user.Roles[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.Roles = DeduplicateRoles(user.Roles)
		}
	case "x509certificates":
		for i := range user.X509Certificates {
			if matchesCertFilter(&user.X509Certificates[i], filterExpr) {
				if err := setCertSubAttribute(&user.X509Certificates[i], subAttr, value); err != nil {
					return err
				}
				if demoteOthers {
					for j := range user.X509Certificates {
						if j != i {
							user.X509Certificates[j].PrimaryFlag = false
						}
					}
				}
				found = true
			}
		}
		if found {
			user.X509Certificates = DeduplicateX509Certificates(user.X509Certificates)
		}
	default:
		return NewScimError(400, "invalidPath", "Unknown collection: "+collection)
	}

	if !found {
		return NewScimError(400, "noTarget", "No matching item found for filter: "+filterExpr)
	}
	return nil
}

// Filter matching

type filterClause struct {
	attr  string
	value string
}

func parseEqFilter(expr string) *filterClause {
	re := regexp.MustCompile(`(?i)(\w+)\s+eq\s+"([^"]*)"`)
	m := re.FindStringSubmatch(expr)
	if m == nil {
		return nil
	}
	return &filterClause{attr: strings.ToLower(m[1]), value: NormalizeNFC(m[2])}
}

func matchesGenericFilter(filterExpr string, value, typ, display string, primary bool) bool {
	fc := parseEqFilter(filterExpr)
	if fc == nil {
		return false
	}
	switch fc.attr {
	case "value":
		return strings.EqualFold(value, fc.value)
	case "type":
		return strings.EqualFold(typ, fc.value)
	case "display":
		return strings.EqualFold(display, fc.value)
	case "primary":
		return strings.EqualFold(fmt.Sprintf("%v", primary), fc.value)
	}
	return false
}

func matchesEmailFilter(e *model.ScimUserEmail, filter string) bool {
	return matchesGenericFilter(filter, e.Value, e.Type, e.Display, e.PrimaryFlag)
}

func matchesPhoneFilter(p *model.ScimUserPhoneNumber, filter string) bool {
	return matchesGenericFilter(filter, p.Value, p.Type, p.Display, p.PrimaryFlag)
}

func matchesAddressFilter(a *model.ScimUserAddress, filter string) bool {
	fc := parseEqFilter(filter)
	if fc == nil {
		return false
	}
	switch fc.attr {
	case "type":
		return strings.EqualFold(a.Type, fc.value)
	case "formatted":
		return strings.EqualFold(a.Formatted, fc.value)
	case "streetaddress":
		return strings.EqualFold(a.StreetAddress, fc.value)
	case "locality":
		return strings.EqualFold(a.Locality, fc.value)
	case "region":
		return strings.EqualFold(a.Region, fc.value)
	case "postalcode":
		return strings.EqualFold(a.PostalCode, fc.value)
	case "country":
		return strings.EqualFold(a.Country, fc.value)
	case "primary":
		return strings.EqualFold(fmt.Sprintf("%v", a.PrimaryFlag), fc.value)
	}
	return false
}

func matchesImFilter(im *model.ScimUserIm, filter string) bool {
	return matchesGenericFilter(filter, im.Value, im.Type, im.Display, im.PrimaryFlag)
}

func matchesPhotoFilter(p *model.ScimUserPhoto, filter string) bool {
	return matchesGenericFilter(filter, p.Value, p.Type, p.Display, p.PrimaryFlag)
}

func matchesEntitlementFilter(e *model.ScimUserEntitlement, filter string) bool {
	return matchesGenericFilter(filter, e.Value, e.Type, e.Display, e.PrimaryFlag)
}

func matchesRoleFilter(r *model.ScimUserRole, filter string) bool {
	return matchesGenericFilter(filter, r.Value, r.Type, r.Display, r.PrimaryFlag)
}

func matchesCertFilter(c *model.ScimUserX509Certificate, filter string) bool {
	return matchesGenericFilter(filter, c.Value, c.Type, c.Display, c.PrimaryFlag)
}

func removeMatching[T any](items []T, filterExpr string, matchFn func(*T, string) bool) []T {
	result := make([]T, 0, len(items))
	for i := range items {
		if !matchFn(&items[i], filterExpr) {
			result = append(result, items[i])
		}
	}
	return result
}

// Sub-attribute setters

func setEmailSubAttribute(e *model.ScimUserEmail, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for emails item")
		}
		for k, v := range m {
			if err := setEmailSubAttribute(e, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "value":
		s, err := parseStrictString(value, "emails.value")
		if err != nil {
			return err
		}
		e.Value = CanonicalizeEmail(s)
	case "type":
		s, err := parseStrictString(value, "emails.type")
		if err != nil {
			return err
		}
		ct := normalizeCanonical(strings.TrimSpace(s), emailTypes)
		if ct == "" {
			ct = "work"
		}
		e.Type = ct
	case "display":
		s, err := parseStrictString(value, "emails.display")
		if err != nil {
			return err
		}
		e.Display = s
	case "primary":
		b, err := parseStrictBool(value, "emails.primary")
		if err != nil {
			return err
		}
		e.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown emails sub-attribute: "+subAttr)
	}
	return nil
}

func setPhoneSubAttribute(p *model.ScimUserPhoneNumber, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for phoneNumbers item")
		}
		for k, v := range m {
			if err := setPhoneSubAttribute(p, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "value":
		s, err := parseStrictString(value, "phoneNumbers.value")
		if err != nil {
			return err
		}
		p.Value = CanonicalizePhoneNumber(s)
	case "type":
		s, err := parseStrictString(value, "phoneNumbers.type")
		if err != nil {
			return err
		}
		p.Type = normalizeCanonical(s, phoneTypes)
	case "display":
		s, err := parseStrictString(value, "phoneNumbers.display")
		if err != nil {
			return err
		}
		p.Display = s
	case "primary":
		b, err := parseStrictBool(value, "phoneNumbers.primary")
		if err != nil {
			return err
		}
		p.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown phoneNumbers sub-attribute: "+subAttr)
	}
	return nil
}

func setAddressSubAttribute(a *model.ScimUserAddress, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for addresses item")
		}
		for k, v := range m {
			if err := setAddressSubAttribute(a, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "formatted":
		s, err := parseStrictString(value, "addresses.formatted")
		if err != nil {
			return err
		}
		a.Formatted = s
	case "streetaddress":
		s, err := parseStrictString(value, "addresses.streetAddress")
		if err != nil {
			return err
		}
		a.StreetAddress = s
	case "locality":
		s, err := parseStrictString(value, "addresses.locality")
		if err != nil {
			return err
		}
		a.Locality = s
	case "region":
		s, err := parseStrictString(value, "addresses.region")
		if err != nil {
			return err
		}
		a.Region = s
	case "postalcode":
		s, err := parseStrictString(value, "addresses.postalCode")
		if err != nil {
			return err
		}
		a.PostalCode = s
	case "country":
		s, err := parseStrictString(value, "addresses.country")
		if err != nil {
			return err
		}
		a.Country = normalizeCountry(s)
	case "type":
		s, err := parseStrictString(value, "addresses.type")
		if err != nil {
			return err
		}
		a.Type = normalizeCanonical(s, addressTypes)
	case "primary":
		b, err := parseStrictBool(value, "addresses.primary")
		if err != nil {
			return err
		}
		a.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown addresses sub-attribute: "+subAttr)
	}
	return nil
}

func setImSubAttribute(im *model.ScimUserIm, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for ims item")
		}
		for k, v := range m {
			if err := setImSubAttribute(im, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "value":
		s, err := parseStrictString(value, "ims.value")
		if err != nil {
			return err
		}
		im.Value = CanonicalizeIM(s)
	case "type":
		s, err := parseStrictString(value, "ims.type")
		if err != nil {
			return err
		}
		im.Type = normalizeCanonical(s, imTypes)
	case "display":
		s, err := parseStrictString(value, "ims.display")
		if err != nil {
			return err
		}
		im.Display = s
	case "primary":
		b, err := parseStrictBool(value, "ims.primary")
		if err != nil {
			return err
		}
		im.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown ims sub-attribute: "+subAttr)
	}
	return nil
}

func setPhotoSubAttribute(p *model.ScimUserPhoto, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for photos item")
		}
		for k, v := range m {
			if err := setPhotoSubAttribute(p, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "value":
		s, err := parseStrictString(value, "photos.value")
		if err != nil {
			return err
		}
		if s != "" {
			if err := validateReference(s); err != nil {
				return err
			}
		}
		p.Value = s
	case "type":
		s, err := parseStrictString(value, "photos.type")
		if err != nil {
			return err
		}
		p.Type = normalizeCanonical(s, photoTypes)
	case "display":
		s, err := parseStrictString(value, "photos.display")
		if err != nil {
			return err
		}
		p.Display = s
	case "primary":
		b, err := parseStrictBool(value, "photos.primary")
		if err != nil {
			return err
		}
		p.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown photos sub-attribute: "+subAttr)
	}
	return nil
}

func setEntitlementSubAttribute(e *model.ScimUserEntitlement, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for entitlements item")
		}
		for k, v := range m {
			if err := setEntitlementSubAttribute(e, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "value":
		s, err := parseStrictString(value, "entitlements.value")
		if err != nil {
			return err
		}
		e.Value = s
	case "type":
		s, err := parseStrictString(value, "entitlements.type")
		if err != nil {
			return err
		}
		e.Type = s
	case "display":
		s, err := parseStrictString(value, "entitlements.display")
		if err != nil {
			return err
		}
		e.Display = s
	case "primary":
		b, err := parseStrictBool(value, "entitlements.primary")
		if err != nil {
			return err
		}
		e.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown entitlements sub-attribute: "+subAttr)
	}
	return nil
}

func setRoleSubAttribute(r *model.ScimUserRole, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for roles item")
		}
		for k, v := range m {
			if err := setRoleSubAttribute(r, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "value":
		s, err := parseStrictString(value, "roles.value")
		if err != nil {
			return err
		}
		r.Value = s
	case "type":
		s, err := parseStrictString(value, "roles.type")
		if err != nil {
			return err
		}
		r.Type = s
	case "display":
		s, err := parseStrictString(value, "roles.display")
		if err != nil {
			return err
		}
		r.Display = s
	case "primary":
		b, err := parseStrictBool(value, "roles.primary")
		if err != nil {
			return err
		}
		r.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown roles sub-attribute: "+subAttr)
	}
	return nil
}

func setCertSubAttribute(c *model.ScimUserX509Certificate, subAttr string, value any) error {
	if subAttr == "" {
		m, ok := value.(map[string]any)
		if !ok {
			return NewScimError(400, "invalidValue", "Expected object value for x509Certificates item")
		}
		for k, v := range m {
			if err := setCertSubAttribute(c, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	switch strings.ToLower(subAttr) {
	case "value":
		rawPtr, err := parseRawStringPtr(value, "x509Certificates.value")
		if err != nil {
			return err
		}
		rawStr := ""
		if rawPtr != nil {
			rawStr = *rawPtr
		}
		if err := ValidateX509CertificateValue(rawStr); err != nil {
			return err
		}
		c.Value = rawStr
	case "type":
		s, err := parseStrictString(value, "x509Certificates.type")
		if err != nil {
			return err
		}
		c.Type = s
	case "display":
		s, err := parseStrictString(value, "x509Certificates.display")
		if err != nil {
			return err
		}
		c.Display = s
	case "primary":
		b, err := parseStrictBool(value, "x509Certificates.primary")
		if err != nil {
			return err
		}
		c.PrimaryFlag = b
	default:
		return NewScimError(400, "invalidPath", "Unknown x509Certificates sub-attribute: "+subAttr)
	}
	return nil
}

// Builders

func buildEmail(m map[string]any) (model.ScimUserEmail, error) {
	val, err := parseStrictString(m["value"], "emails.value")
	if err != nil {
		return model.ScimUserEmail{}, err
	}
	rawType, err := parseStrictString(m["type"], "emails.type")
	if err != nil {
		return model.ScimUserEmail{}, err
	}
	disp, err := parseStrictString(m["display"], "emails.display")
	if err != nil {
		return model.ScimUserEmail{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "emails.primary")
	if err != nil {
		return model.ScimUserEmail{}, err
	}
	emailType := normalizeCanonical(strings.TrimSpace(rawType), emailTypes)
	if emailType == "" {
		emailType = "work"
	}
	return model.ScimUserEmail{
		Value:       CanonicalizeEmail(val),
		Type:        emailType,
		Display:     disp,
		PrimaryFlag: prim,
	}, nil
}

func buildPhoneNumber(m map[string]any) (model.ScimUserPhoneNumber, error) {
	val, err := parseStrictString(m["value"], "phoneNumbers.value")
	if err != nil {
		return model.ScimUserPhoneNumber{}, err
	}
	rawType, err := parseStrictString(m["type"], "phoneNumbers.type")
	if err != nil {
		return model.ScimUserPhoneNumber{}, err
	}
	disp, err := parseStrictString(m["display"], "phoneNumbers.display")
	if err != nil {
		return model.ScimUserPhoneNumber{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "phoneNumbers.primary")
	if err != nil {
		return model.ScimUserPhoneNumber{}, err
	}
	return model.ScimUserPhoneNumber{
		Value:       CanonicalizePhoneNumber(val),
		Type:        normalizeCanonical(rawType, phoneTypes),
		Display:     disp,
		PrimaryFlag: prim,
	}, nil
}

var isoAlpha3ToAlpha2 = map[string]string{
	"USA": "US", "GBR": "GB", "DEU": "DE", "FRA": "FR", "CAN": "CA",
	"AUS": "AU", "JPN": "JP", "SWE": "SE", "CHE": "CH", "AUT": "AT",
	"ITA": "IT", "ESP": "ES", "NLD": "NL", "BEL": "BE", "DNK": "DK",
	"NOR": "NO", "FIN": "FI", "POL": "PL", "IRL": "IE", "PRT": "PT",
	"BRA": "BR", "MEX": "MX", "IND": "IN", "CHN": "CN", "KOR": "KR",
	"SGP": "SG", "NZL": "NZ",
}

func normalizeCountry(raw string) string {
	c := strings.ToUpper(strings.TrimSpace(raw))
	if c == "" {
		return ""
	}
	if len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z' {
		return c
	}
	if alpha2, ok := isoAlpha3ToAlpha2[c]; ok {
		return alpha2
	}
	return ""
}

func buildAddress(m map[string]any) (model.ScimUserAddress, error) {
	formatted, err := parseStrictString(m["formatted"], "addresses.formatted")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	street, err := parseStrictString(m["streetAddress"], "addresses.streetAddress")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	locality, err := parseStrictString(m["locality"], "addresses.locality")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	region, err := parseStrictString(m["region"], "addresses.region")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	postal, err := parseStrictString(m["postalCode"], "addresses.postalCode")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	country, err := parseStrictString(m["country"], "addresses.country")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	rawType, err := parseStrictString(m["type"], "addresses.type")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "addresses.primary")
	if err != nil {
		return model.ScimUserAddress{}, err
	}
	return model.ScimUserAddress{
		Formatted:     formatted,
		StreetAddress: street,
		Locality:      locality,
		Region:        region,
		PostalCode:    postal,
		Country:       normalizeCountry(country),
		Type:          normalizeCanonical(rawType, addressTypes),
		PrimaryFlag:   prim,
	}, nil
}

func buildIm(m map[string]any) (model.ScimUserIm, error) {
	val, err := parseStrictString(m["value"], "ims.value")
	if err != nil {
		return model.ScimUserIm{}, err
	}
	rawType, err := parseStrictString(m["type"], "ims.type")
	if err != nil {
		return model.ScimUserIm{}, err
	}
	disp, err := parseStrictString(m["display"], "ims.display")
	if err != nil {
		return model.ScimUserIm{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "ims.primary")
	if err != nil {
		return model.ScimUserIm{}, err
	}
	return model.ScimUserIm{
		Value:       CanonicalizeIM(val),
		Type:        normalizeCanonical(rawType, imTypes),
		Display:     disp,
		PrimaryFlag: prim,
	}, nil
}

func buildPhoto(m map[string]any) (model.ScimUserPhoto, error) {
	v, err := parseStrictString(m["value"], "photos.value")
	if err != nil {
		return model.ScimUserPhoto{}, err
	}
	if v != "" {
		if err := validateReference(v); err != nil {
			return model.ScimUserPhoto{}, err
		}
	}
	rawType, err := parseStrictString(m["type"], "photos.type")
	if err != nil {
		return model.ScimUserPhoto{}, err
	}
	disp, err := parseStrictString(m["display"], "photos.display")
	if err != nil {
		return model.ScimUserPhoto{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "photos.primary")
	if err != nil {
		return model.ScimUserPhoto{}, err
	}
	return model.ScimUserPhoto{
		Value:       v,
		Type:        normalizeCanonical(rawType, photoTypes),
		Display:     disp,
		PrimaryFlag: prim,
	}, nil
}

func buildEntitlement(m map[string]any) (model.ScimUserEntitlement, error) {
	val, err := parseStrictString(m["value"], "entitlements.value")
	if err != nil {
		return model.ScimUserEntitlement{}, err
	}
	rawType, err := parseStrictString(m["type"], "entitlements.type")
	if err != nil {
		return model.ScimUserEntitlement{}, err
	}
	disp, err := parseStrictString(m["display"], "entitlements.display")
	if err != nil {
		return model.ScimUserEntitlement{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "entitlements.primary")
	if err != nil {
		return model.ScimUserEntitlement{}, err
	}
	return model.ScimUserEntitlement{
		Value:       val,
		Type:        rawType,
		Display:     disp,
		PrimaryFlag: prim,
	}, nil
}

func buildRole(m map[string]any) (model.ScimUserRole, error) {
	val, err := parseStrictString(m["value"], "roles.value")
	if err != nil {
		return model.ScimUserRole{}, err
	}
	rawType, err := parseStrictString(m["type"], "roles.type")
	if err != nil {
		return model.ScimUserRole{}, err
	}
	disp, err := parseStrictString(m["display"], "roles.display")
	if err != nil {
		return model.ScimUserRole{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "roles.primary")
	if err != nil {
		return model.ScimUserRole{}, err
	}
	return model.ScimUserRole{
		Value:       val,
		Type:        rawType,
		Display:     disp,
		PrimaryFlag: prim,
	}, nil
}

func buildX509Certificate(m map[string]any) (model.ScimUserX509Certificate, error) {
	rawPtr, err := parseRawStringPtr(m["value"], "x509Certificates.value")
	if err != nil {
		return model.ScimUserX509Certificate{}, err
	}
	v := ""
	if rawPtr != nil {
		v = *rawPtr
	}
	if _, hasVal := m["value"]; hasVal || v != "" {
		if err := ValidateX509CertificateValue(v); err != nil {
			return model.ScimUserX509Certificate{}, err
		}
	}
	rawType, err := parseStrictString(m["type"], "x509Certificates.type")
	if err != nil {
		return model.ScimUserX509Certificate{}, err
	}
	disp, err := parseStrictString(m["display"], "x509Certificates.display")
	if err != nil {
		return model.ScimUserX509Certificate{}, err
	}
	prim, err := parseStrictOptionalBool(m["primary"], "x509Certificates.primary")
	if err != nil {
		return model.ScimUserX509Certificate{}, err
	}
	return model.ScimUserX509Certificate{
		Value:       v,
		Type:        rawType,
		Display:     disp,
		PrimaryFlag: prim,
	}, nil
}

// Helpers

func toItemList(value any) ([]map[string]any, error) {
	switch v := value.(type) {
	case []any:
		result := make([]map[string]any, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, NewScimError(400, "invalidValue", "Expected object elements in multi-valued attribute array")
			}
			result = append(result, m)
		}
		return result, nil
	case []map[string]any:
		return v, nil
	case map[string]any:
		return []map[string]any{v}, nil
	default:
		return nil, NewScimError(400, "invalidValue", "Expected array or object for multi-valued attribute")
	}
}

func normalizeCanonical(val string, validTypes map[string]bool) string {
	if val == "" {
		return val
	}
	for k := range validTypes {
		if strings.EqualFold(val, k) {
			return k
		}
	}
	return val
}

func validateReference(val string) error {
	if val == "" {
		return nil
	}
	if strings.ContainsAny(val, " \t\r\n") {
		return NewScimError(400, "invalidValue", "Invalid reference URI (contains whitespace): "+val)
	}
	if _, err := url.Parse(val); err != nil {
		return NewScimError(400, "invalidValue", "Invalid reference URI: "+val)
	}
	return nil
}

func validateBinary(val string) error {
	if val == "" {
		return nil
	}
	_, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		_, err2 := base64.RawStdEncoding.DecodeString(val)
		if err2 != nil {
			return NewScimError(400, "invalidValue", "Invalid binary value (must be base64): "+val)
		}
	}
	return nil
}

func parseStrictBool(value any, attrName string) (bool, error) {
	b, ok := value.(bool)
	if !ok {
		return false, NewScimError(400, "invalidValue", fmt.Sprintf("Attribute '%s' must be a boolean", attrName))
	}
	return b, nil
}

func parseStrictOptionalBool(value any, attrName string) (bool, error) {
	if value == nil {
		return false, nil
	}
	return parseStrictBool(value, attrName)
}

func parseStrictStringPtr(value any, attrName string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	s, ok := value.(string)
	if !ok {
		return nil, NewScimError(400, "invalidValue", fmt.Sprintf("Attribute '%s' must be a string", attrName))
	}
	normStr := NormalizeNFC(s)
	return &normStr, nil
}

func parseRawStringPtr(value any, attrName string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	s, ok := value.(string)
	if !ok {
		return nil, NewScimError(400, "invalidValue", fmt.Sprintf("Attribute '%s' must be a string", attrName))
	}
	return &s, nil
}

func parseStrictString(value any, attrName string) (string, error) {
	if value == nil {
		return "", nil
	}
	s, ok := value.(string)
	if !ok {
		return "", NewScimError(400, "invalidValue", fmt.Sprintf("Attribute '%s' must be a string", attrName))
	}
	return NormalizeNFC(s), nil
}

func toStringPtr(value any) *string {
	if value == nil {
		return nil
	}
	s := fmt.Sprintf("%v", value)
	return &s
}

func toStr(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func toBool(value any) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}
