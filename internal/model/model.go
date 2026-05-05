package model

import (
	"time"

	"github.com/google/uuid"
)

// Workspace represents a tenant workspace.
type Workspace struct {
	ID                uuid.UUID
	Name              string
	Description       *string
	CreatedByUsername  *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// WorkspaceToken represents a bearer token for SCIM API access.
type WorkspaceToken struct {
	ID          uuid.UUID
	WorkspaceID uuid.UUID
	TokenHash   string
	Name        *string
	Description *string
	ExpiresAt   *time.Time
	Revoked     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ScimUser represents a SCIM 2.0 User resource.
type ScimUser struct {
	ID                       uuid.UUID
	WorkspaceID              uuid.UUID
	UserName                 string
	ExternalID               *string
	NameFormatted            *string
	NameFamilyName           *string
	NameGivenName            *string
	NameMiddleName           *string
	NameHonorificPrefix      *string
	NameHonorificSuffix      *string
	DisplayName              *string
	NickName                 *string
	ProfileUrl               *string
	Title                    *string
	UserType                 *string
	PreferredLanguage        *string
	Locale                   *string
	Timezone                 *string
	Active                   bool
	Password                 *string
	EnterpriseEmployeeNumber *string
	EnterpriseCostCenter     *string
	EnterpriseOrganization   *string
	EnterpriseDivision       *string
	EnterpriseDepartment     *string
	EnterpriseManagerValue   *string
	EnterpriseManagerRef     *string
	EnterpriseManagerDisplay *string
	CreatedAt                time.Time
	LastModified             time.Time
	Version                  int64
	Emails                   []ScimUserEmail
	PhoneNumbers             []ScimUserPhoneNumber
	Addresses                []ScimUserAddress
	Entitlements             []ScimUserEntitlement
	Roles                    []ScimUserRole
	Ims                      []ScimUserIm
	Photos                   []ScimUserPhoto
	X509Certificates         []ScimUserX509Certificate
}

// ScimUserEmail represents an email entry in the JSON emails column.
type ScimUserEmail struct {
	Value       string `json:"value,omitempty"`
	Type        string `json:"type,omitempty"`
	Display     string `json:"display,omitempty"`
	PrimaryFlag bool   `json:"primaryFlag"`
}

// ScimUserPhoneNumber represents a phone number entry.
type ScimUserPhoneNumber struct {
	Value       string `json:"value,omitempty"`
	Type        string `json:"type,omitempty"`
	Display     string `json:"display,omitempty"`
	PrimaryFlag bool   `json:"primaryFlag"`
}

// ScimUserAddress represents an address entry.
type ScimUserAddress struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	Country       string `json:"country,omitempty"`
	Type          string `json:"type,omitempty"`
	PrimaryFlag   bool   `json:"primaryFlag"`
}

// ScimUserEntitlement represents an entitlement entry.
type ScimUserEntitlement struct {
	Value       string `json:"value,omitempty"`
	Type        string `json:"type,omitempty"`
	Display     string `json:"display,omitempty"`
	PrimaryFlag bool   `json:"primaryFlag"`
}

// ScimUserRole represents a role entry.
type ScimUserRole struct {
	Value       string `json:"value,omitempty"`
	Type        string `json:"type,omitempty"`
	Display     string `json:"display,omitempty"`
	PrimaryFlag bool   `json:"primaryFlag"`
}

// ScimUserIm represents an IM entry.
type ScimUserIm struct {
	Value       string `json:"value,omitempty"`
	Type        string `json:"type,omitempty"`
	Display     string `json:"display,omitempty"`
	PrimaryFlag bool   `json:"primaryFlag"`
}

// ScimUserPhoto represents a photo entry.
type ScimUserPhoto struct {
	Value       string `json:"value,omitempty"`
	Type        string `json:"type,omitempty"`
	Display     string `json:"display,omitempty"`
	PrimaryFlag bool   `json:"primaryFlag"`
}

// ScimUserX509Certificate represents an x509 certificate entry.
type ScimUserX509Certificate struct {
	Value       string `json:"value,omitempty"`
	Type        string `json:"type,omitempty"`
	Display     string `json:"display,omitempty"`
	PrimaryFlag bool   `json:"primaryFlag"`
}

// ScimGroup represents a SCIM 2.0 Group resource.
type ScimGroup struct {
	ID           uuid.UUID
	WorkspaceID  uuid.UUID
	ExternalID   *string
	DisplayName  string
	CreatedAt    time.Time
	LastModified time.Time
	Version      int64
	Members      []ScimGroupMembership
}

// ScimGroupMembership represents a group membership.
type ScimGroupMembership struct {
	ID          uuid.UUID
	GroupID     uuid.UUID
	WorkspaceID uuid.UUID
	MemberValue uuid.UUID
	MemberType  *string
	Display     *string
}

// ScimRequestLog represents a logged SCIM request.
type ScimRequestLog struct {
	ID           uuid.UUID
	WorkspaceID  uuid.UUID
	HttpMethod   string
	RequestPath  string
	HttpStatus   int
	RequestBody  *string
	ResponseBody *string
	CreatedAt    time.Time
}
