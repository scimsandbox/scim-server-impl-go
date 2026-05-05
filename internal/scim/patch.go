package scim

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

var readOnlyAttrs = map[string]bool{
	"id": true, "meta": true, "meta.created": true, "meta.lastmodified": true,
	"meta.location": true, "meta.resourcetype": true, "meta.version": true,
	"groups": true,
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
	coreUser := "urn:ietf:params:scim:schemas:core:2.0:User:"
	if strings.HasPrefix(path, coreUser) {
		return path[len(coreUser):]
	}
	if strings.HasPrefix(path, enterpriseSchemaURN+":") {
		return path[len(enterpriseSchemaURN)+1:]
	}
	if path == enterpriseSchemaURN {
		return path
	}
	return path
}

func applyAdd(user *model.ScimUser, path string, value any) error {
	if path == "" {
		return applyValueMap(user, value)
	}
	m := filteredPathRegex.FindStringSubmatch(path)
	if m != nil {
		return applyFilteredAdd(user, m[1], m[2], m[3], value)
	}
	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, enterpriseSchemaURN) || isEnterpriseAttr(path) {
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
		return applyValueMap(user, value)
	}
	m := filteredPathRegex.FindStringSubmatch(path)
	if m != nil {
		return applyFilteredReplace(user, m[1], m[2], m[3], value)
	}
	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, enterpriseSchemaURN) || isEnterpriseAttr(path) {
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
	if strings.HasPrefix(lower, enterpriseSchemaURN) || isEnterpriseAttr(path) {
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
	s := toStringPtr(value)
	switch strings.ToLower(path) {
	case "username":
		if s == nil {
			return NewScimError(400, "invalidValue", "userName cannot be null")
		}
		user.UserName = *s
	case "externalid":
		user.ExternalID = s
	case "displayname":
		user.DisplayName = s
	case "nickname":
		user.NickName = s
	case "profileurl":
		if s != nil {
			if err := validateReference(*s); err != nil {
				return err
			}
		}
		user.ProfileUrl = s
	case "title":
		user.Title = s
	case "usertype":
		user.UserType = s
	case "preferredlanguage":
		user.PreferredLanguage = s
	case "locale":
		user.Locale = s
	case "timezone":
		user.Timezone = s
	case "active":
		user.Active = toBool(value)
	case "password":
		user.Password = s
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

	if parent != "name" {
		return NewScimError(400, "invalidPath", "Unknown complex attribute: "+parts[0])
	}

	s := toStringPtr(value)
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

func setEnterpriseAttribute(user *model.ScimUser, path string, value any) error {
	attr := path
	if strings.HasPrefix(path, enterpriseSchemaURN+":") {
		attr = path[len(enterpriseSchemaURN)+1:]
	} else if path == enterpriseSchemaURN {
		return applyEnterpriseValueMap(user, value)
	}

	s := toStringPtr(value)
	switch strings.ToLower(attr) {
	case "employeenumber":
		user.EnterpriseEmployeeNumber = s
	case "costcenter":
		user.EnterpriseCostCenter = s
	case "organization":
		user.EnterpriseOrganization = s
	case "division":
		user.EnterpriseDivision = s
	case "department":
		user.EnterpriseDepartment = s
	case "manager":
		return setEnterpriseManager(user, value)
	case "manager.value":
		user.EnterpriseManagerValue = s
	case "manager.$ref":
		user.EnterpriseManagerRef = s
	case "manager.displayname":
		user.EnterpriseManagerDisplay = s
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
		user.EnterpriseManagerValue = &v
	case map[string]any:
		if val, ok := v["value"]; ok {
			user.EnterpriseManagerValue = toStringPtr(val)
		}
		if ref, ok := v["$ref"]; ok {
			user.EnterpriseManagerRef = toStringPtr(ref)
		}
		if disp, ok := v["displayName"]; ok {
			user.EnterpriseManagerDisplay = toStringPtr(disp)
		}
	default:
		s := fmt.Sprintf("%v", value)
		user.EnterpriseManagerValue = &s
	}
	return nil
}

func applyEnterpriseValueMap(user *model.ScimUser, value any) error {
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
	if strings.HasPrefix(path, enterpriseSchemaURN+":") {
		attr = path[len(enterpriseSchemaURN)+1:]
	} else if strings.EqualFold(path, enterpriseSchemaURN) {
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

func applyValueMap(user *model.ScimUser, value any) error {
	m, ok := value.(map[string]any)
	if !ok {
		return NewScimError(400, "invalidValue", "PATCH add/replace without path requires a value object")
	}
	for k, v := range m {
		key := stripPatchURNPrefix(k)
		lower := strings.ToLower(key)
		if key == enterpriseSchemaURN || strings.HasPrefix(key, enterpriseSchemaURN) {
			if err := setEnterpriseAttribute(user, key, v); err != nil {
				return err
			}
		} else if strings.Contains(key, ".") {
			if err := setSubAttribute(user, key, v); err != nil {
				return err
			}
		} else if multiValuedAttrs[lower] {
			if err := addToMultiValued(user, lower, v); err != nil {
				return err
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
	switch attr {
	case "emails":
		for _, item := range items {
			user.Emails = append(user.Emails, buildEmail(item))
		}
	case "phonenumbers":
		for _, item := range items {
			user.PhoneNumbers = append(user.PhoneNumbers, buildPhoneNumber(item))
		}
	case "addresses":
		for _, item := range items {
			user.Addresses = append(user.Addresses, buildAddress(item))
		}
	case "ims":
		for _, item := range items {
			user.Ims = append(user.Ims, buildIm(item))
		}
	case "photos":
		for _, item := range items {
			user.Photos = append(user.Photos, buildPhoto(item))
		}
	case "entitlements":
		for _, item := range items {
			user.Entitlements = append(user.Entitlements, buildEntitlement(item))
		}
	case "roles":
		for _, item := range items {
			user.Roles = append(user.Roles, buildRole(item))
		}
	case "x509certificates":
		for _, item := range items {
			user.X509Certificates = append(user.X509Certificates, buildX509Certificate(item))
		}
	}
	return nil
}

func replaceMultiValued(user *model.ScimUser, attr string, value any) error {
	clearAttribute(user, attr)
	return addToMultiValued(user, attr, value)
}

func clearAttribute(user *model.ScimUser, attr string) error {
	switch strings.ToLower(attr) {
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

func applyFilteredUpdate(user *model.ScimUser, collection, filterExpr, subAttr string, value any) error {
	fc := parseEqFilter(filterExpr)
	if fc == nil {
		return NewScimError(400, "invalidFilter", "Cannot parse filter: "+filterExpr)
	}
	found := false

	switch collection {
	case "emails":
		for i := range user.Emails {
			if matchesEmailFilter(&user.Emails[i], filterExpr) {
				setEmailSubAttribute(&user.Emails[i], subAttr, value)
				found = true
			}
		}
	case "phonenumbers":
		for i := range user.PhoneNumbers {
			if matchesPhoneFilter(&user.PhoneNumbers[i], filterExpr) {
				setPhoneSubAttribute(&user.PhoneNumbers[i], subAttr, value)
				found = true
			}
		}
	case "addresses":
		for i := range user.Addresses {
			if matchesAddressFilter(&user.Addresses[i], filterExpr) {
				setAddressSubAttribute(&user.Addresses[i], subAttr, value)
				found = true
			}
		}
	case "ims":
		for i := range user.Ims {
			if matchesImFilter(&user.Ims[i], filterExpr) {
				setImSubAttribute(&user.Ims[i], subAttr, value)
				found = true
			}
		}
	case "photos":
		for i := range user.Photos {
			if matchesPhotoFilter(&user.Photos[i], filterExpr) {
				setPhotoSubAttribute(&user.Photos[i], subAttr, value)
				found = true
			}
		}
	case "entitlements":
		for i := range user.Entitlements {
			if matchesEntitlementFilter(&user.Entitlements[i], filterExpr) {
				setEntitlementSubAttribute(&user.Entitlements[i], subAttr, value)
				found = true
			}
		}
	case "roles":
		for i := range user.Roles {
			if matchesRoleFilter(&user.Roles[i], filterExpr) {
				setRoleSubAttribute(&user.Roles[i], subAttr, value)
				found = true
			}
		}
	case "x509certificates":
		for i := range user.X509Certificates {
			if matchesCertFilter(&user.X509Certificates[i], filterExpr) {
				setCertSubAttribute(&user.X509Certificates[i], subAttr, value)
				found = true
			}
		}
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
	return &filterClause{attr: strings.ToLower(m[1]), value: m[2]}
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

func setEmailSubAttribute(e *model.ScimUserEmail, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "value":
		e.Value = s
	case "type":
		e.Type = normalizeCanonical(s, emailTypes)
	case "display":
		e.Display = s
	case "primary":
		e.PrimaryFlag = toBool(value)
	}
}

func setPhoneSubAttribute(p *model.ScimUserPhoneNumber, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "value":
		p.Value = s
	case "type":
		p.Type = normalizeCanonical(s, phoneTypes)
	case "display":
		p.Display = s
	case "primary":
		p.PrimaryFlag = toBool(value)
	}
}

func setAddressSubAttribute(a *model.ScimUserAddress, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "formatted":
		a.Formatted = s
	case "streetaddress":
		a.StreetAddress = s
	case "locality":
		a.Locality = s
	case "region":
		a.Region = s
	case "postalcode":
		a.PostalCode = s
	case "country":
		a.Country = s
	case "type":
		a.Type = normalizeCanonical(s, addressTypes)
	case "primary":
		a.PrimaryFlag = toBool(value)
	}
}

func setImSubAttribute(im *model.ScimUserIm, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "value":
		im.Value = s
	case "type":
		im.Type = normalizeCanonical(s, imTypes)
	case "display":
		im.Display = s
	case "primary":
		im.PrimaryFlag = toBool(value)
	}
}

func setPhotoSubAttribute(p *model.ScimUserPhoto, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "value":
		if s != "" {
			if err := validateReference(s); err != nil {
				return
			}
		}
		p.Value = s
	case "type":
		p.Type = normalizeCanonical(s, photoTypes)
	case "display":
		p.Display = s
	case "primary":
		p.PrimaryFlag = toBool(value)
	}
}

func setEntitlementSubAttribute(e *model.ScimUserEntitlement, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "value":
		e.Value = s
	case "type":
		e.Type = s
	case "display":
		e.Display = s
	case "primary":
		e.PrimaryFlag = toBool(value)
	}
}

func setRoleSubAttribute(r *model.ScimUserRole, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "value":
		r.Value = s
	case "type":
		r.Type = s
	case "display":
		r.Display = s
	case "primary":
		r.PrimaryFlag = toBool(value)
	}
}

func setCertSubAttribute(c *model.ScimUserX509Certificate, subAttr string, value any) {
	s := toStr(value)
	switch strings.ToLower(subAttr) {
	case "value":
		if s != "" {
			validateBinary(s)
		}
		c.Value = s
	case "type":
		c.Type = s
	case "display":
		c.Display = s
	case "primary":
		c.PrimaryFlag = toBool(value)
	}
}

// Builders

func buildEmail(m map[string]any) model.ScimUserEmail {
	return model.ScimUserEmail{
		Value:       toStr(m["value"]),
		Type:        normalizeCanonical(toStr(m["type"]), emailTypes),
		Display:     toStr(m["display"]),
		PrimaryFlag: toBool(m["primary"]),
	}
}

func buildPhoneNumber(m map[string]any) model.ScimUserPhoneNumber {
	return model.ScimUserPhoneNumber{
		Value:       toStr(m["value"]),
		Type:        normalizeCanonical(toStr(m["type"]), phoneTypes),
		Display:     toStr(m["display"]),
		PrimaryFlag: toBool(m["primary"]),
	}
}

func buildAddress(m map[string]any) model.ScimUserAddress {
	return model.ScimUserAddress{
		Formatted:     toStr(m["formatted"]),
		StreetAddress: toStr(m["streetAddress"]),
		Locality:      toStr(m["locality"]),
		Region:        toStr(m["region"]),
		PostalCode:    toStr(m["postalCode"]),
		Country:       toStr(m["country"]),
		Type:          normalizeCanonical(toStr(m["type"]), addressTypes),
		PrimaryFlag:   toBool(m["primary"]),
	}
}

func buildIm(m map[string]any) model.ScimUserIm {
	return model.ScimUserIm{
		Value:       toStr(m["value"]),
		Type:        normalizeCanonical(toStr(m["type"]), imTypes),
		Display:     toStr(m["display"]),
		PrimaryFlag: toBool(m["primary"]),
	}
}

func buildPhoto(m map[string]any) model.ScimUserPhoto {
	v := toStr(m["value"])
	if v != "" {
		validateReference(v)
	}
	return model.ScimUserPhoto{
		Value:       v,
		Type:        normalizeCanonical(toStr(m["type"]), photoTypes),
		Display:     toStr(m["display"]),
		PrimaryFlag: toBool(m["primary"]),
	}
}

func buildEntitlement(m map[string]any) model.ScimUserEntitlement {
	return model.ScimUserEntitlement{
		Value:       toStr(m["value"]),
		Type:        toStr(m["type"]),
		Display:     toStr(m["display"]),
		PrimaryFlag: toBool(m["primary"]),
	}
}

func buildRole(m map[string]any) model.ScimUserRole {
	return model.ScimUserRole{
		Value:       toStr(m["value"]),
		Type:        toStr(m["type"]),
		Display:     toStr(m["display"]),
		PrimaryFlag: toBool(m["primary"]),
	}
}

func buildX509Certificate(m map[string]any) model.ScimUserX509Certificate {
	v := toStr(m["value"])
	if v != "" {
		validateBinary(v)
	}
	return model.ScimUserX509Certificate{
		Value:       v,
		Type:        toStr(m["type"]),
		Display:     toStr(m["display"]),
		PrimaryFlag: toBool(m["primary"]),
	}
}

// Helpers

func toItemList(value any) ([]map[string]any, error) {
	switch v := value.(type) {
	case []any:
		result := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				result = append(result, m)
			}
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
	u, err := url.Parse(val)
	if err != nil || !u.IsAbs() {
		return NewScimError(400, "invalidValue", "Invalid reference value (must be absolute URI): "+val)
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
