package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

type rowScanner interface {
	Scan(dest ...any) error
}

type UserRepository struct{}

func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

var userColumns = `id, workspace_id, user_name, external_id,
	name_formatted, name_family_name, name_given_name, name_middle_name,
	name_honorific_prefix, name_honorific_suffix,
	display_name, nick_name, profile_url, title, user_type,
	preferred_language, locale, timezone, active, password,
	enterprise_employee_number, enterprise_cost_center, enterprise_organization,
	enterprise_division, enterprise_department,
	enterprise_manager_value, enterprise_manager_ref, enterprise_manager_display,
	emails, phone_numbers, addresses, entitlements, roles, ims, photos, x509_certificates,
	created_at, last_modified, version`

func scanUser(row rowScanner) (*model.ScimUser, error) {
	var u model.ScimUser
	var emailsJSON, phonesJSON, addressesJSON, entitlementsJSON, rolesJSON, imsJSON, photosJSON, certsJSON []byte

	err := row.Scan(
		&u.ID, &u.WorkspaceID, &u.UserName, &u.ExternalID,
		&u.NameFormatted, &u.NameFamilyName, &u.NameGivenName, &u.NameMiddleName,
		&u.NameHonorificPrefix, &u.NameHonorificSuffix,
		&u.DisplayName, &u.NickName, &u.ProfileUrl, &u.Title, &u.UserType,
		&u.PreferredLanguage, &u.Locale, &u.Timezone, &u.Active, &u.Password,
		&u.EnterpriseEmployeeNumber, &u.EnterpriseCostCenter, &u.EnterpriseOrganization,
		&u.EnterpriseDivision, &u.EnterpriseDepartment,
		&u.EnterpriseManagerValue, &u.EnterpriseManagerRef, &u.EnterpriseManagerDisplay,
		&emailsJSON, &phonesJSON, &addressesJSON, &entitlementsJSON,
		&rolesJSON, &imsJSON, &photosJSON, &certsJSON,
		&u.CreatedAt, &u.LastModified, &u.Version,
	)
	if err != nil {
		return nil, err
	}

	u.Emails = unmarshalJSON[model.ScimUserEmail](emailsJSON)
	u.PhoneNumbers = unmarshalJSON[model.ScimUserPhoneNumber](phonesJSON)
	u.Addresses = unmarshalJSON[model.ScimUserAddress](addressesJSON)
	u.Entitlements = unmarshalJSON[model.ScimUserEntitlement](entitlementsJSON)
	u.Roles = unmarshalJSON[model.ScimUserRole](rolesJSON)
	u.Ims = unmarshalJSON[model.ScimUserIm](imsJSON)
	u.Photos = unmarshalJSON[model.ScimUserPhoto](photosJSON)
	u.X509Certificates = unmarshalJSON[model.ScimUserX509Certificate](certsJSON)

	return &u, nil
}

func (r *UserRepository) FindByIDAndWorkspaceID(ctx context.Context, id, workspaceID uuid.UUID) (*model.ScimUser, error) {
	query := `SELECT ` + userColumns + ` FROM scim_users WHERE id = $1 AND workspace_id = $2`
	row := jdbc.QueryRowContext(ctx, query, id, workspaceID)
	u, err := scanUser(row)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (r *UserRepository) ExistsByUserNameAndWorkspaceID(ctx context.Context, userName string, workspaceID uuid.UUID) (bool, error) {
	var exists bool
	err := jdbc.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM scim_users WHERE LOWER(user_name) = LOWER($1) AND workspace_id = $2)`,
		userName, workspaceID).Scan(&exists)
	if errors.Is(err, jdbc.ErrNoRows) {
		return false, nil
	}
	return exists, err
}

func (r *UserRepository) Create(ctx context.Context, u *model.ScimUser) error {
	u.ID = uuid.New()
	now := time.Now().UTC()
	u.CreatedAt = now
	u.LastModified = now
	u.Version = 0

	query := `INSERT INTO scim_users (` + userColumns + `)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39)`

	_, err := jdbc.ExecContext(ctx, query,
		u.ID, u.WorkspaceID, u.UserName, u.ExternalID,
		u.NameFormatted, u.NameFamilyName, u.NameGivenName, u.NameMiddleName,
		u.NameHonorificPrefix, u.NameHonorificSuffix,
		u.DisplayName, u.NickName, u.ProfileUrl, u.Title, u.UserType,
		u.PreferredLanguage, u.Locale, u.Timezone, u.Active, u.Password,
		u.EnterpriseEmployeeNumber, u.EnterpriseCostCenter, u.EnterpriseOrganization,
		u.EnterpriseDivision, u.EnterpriseDepartment,
		u.EnterpriseManagerValue, u.EnterpriseManagerRef, u.EnterpriseManagerDisplay,
		marshalJSON(u.Emails), marshalJSON(u.PhoneNumbers), marshalJSON(u.Addresses),
		marshalJSON(u.Entitlements), marshalJSON(u.Roles), marshalJSON(u.Ims),
		marshalJSON(u.Photos), marshalJSON(u.X509Certificates),
		u.CreatedAt, u.LastModified, u.Version,
	)
	return err
}

func (r *UserRepository) Update(ctx context.Context, u *model.ScimUser) error {
	u.LastModified = time.Now().UTC()
	oldVersion := u.Version
	u.Version++

	query := `UPDATE scim_users SET
		user_name=$1, external_id=$2,
		name_formatted=$3, name_family_name=$4, name_given_name=$5, name_middle_name=$6,
		name_honorific_prefix=$7, name_honorific_suffix=$8,
		display_name=$9, nick_name=$10, profile_url=$11, title=$12, user_type=$13,
		preferred_language=$14, locale=$15, timezone=$16, active=$17, password=$18,
		enterprise_employee_number=$19, enterprise_cost_center=$20, enterprise_organization=$21,
		enterprise_division=$22, enterprise_department=$23,
		enterprise_manager_value=$24, enterprise_manager_ref=$25, enterprise_manager_display=$26,
		emails=$27, phone_numbers=$28, addresses=$29, entitlements=$30, roles=$31,
		ims=$32, photos=$33, x509_certificates=$34,
		last_modified=$35, version=$36
		WHERE id=$37 AND version=$38`

	tag, err := jdbc.ExecContext(ctx, query,
		u.UserName, u.ExternalID,
		u.NameFormatted, u.NameFamilyName, u.NameGivenName, u.NameMiddleName,
		u.NameHonorificPrefix, u.NameHonorificSuffix,
		u.DisplayName, u.NickName, u.ProfileUrl, u.Title, u.UserType,
		u.PreferredLanguage, u.Locale, u.Timezone, u.Active, u.Password,
		u.EnterpriseEmployeeNumber, u.EnterpriseCostCenter, u.EnterpriseOrganization,
		u.EnterpriseDivision, u.EnterpriseDepartment,
		u.EnterpriseManagerValue, u.EnterpriseManagerRef, u.EnterpriseManagerDisplay,
		marshalJSON(u.Emails), marshalJSON(u.PhoneNumbers), marshalJSON(u.Addresses),
		marshalJSON(u.Entitlements), marshalJSON(u.Roles),
		marshalJSON(u.Ims), marshalJSON(u.Photos), marshalJSON(u.X509Certificates),
		u.LastModified, u.Version,
		u.ID, oldVersion,
	)
	if err != nil {
		return err
	}
	if tag != nil {
		rowsAffected, err := tag.RowsAffected()
		if err != nil {
			return err
		}
		if rowsAffected == 0 {
			return ErrOptimisticLock
		}
	}
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id, workspaceID uuid.UUID) error {
	_, err := jdbc.ExecContext(ctx,
		`DELETE FROM scim_users WHERE id = $1 AND workspace_id = $2`, id, workspaceID)
	return err
}

func (r *UserRepository) Count(ctx context.Context, workspaceID uuid.UUID, whereClause string, args []any) (int64, error) {
	query := `SELECT COUNT(*) FROM scim_users WHERE workspace_id = $1`
	queryArgs := []any{workspaceID}

	if whereClause != "" {
		query += " AND " + whereClause
		queryArgs = append(queryArgs, args...)
	}

	var count int64
	err := jdbc.QueryRowContext(ctx, query, queryArgs...).Scan(&count)
	return count, err
}

func (r *UserRepository) List(ctx context.Context, workspaceID uuid.UUID, whereClause string, filterArgs []any,
	sortAttr, sortDir string, offset, limit int) ([]*model.ScimUser, error) {

	query := `SELECT ` + userColumns + ` FROM scim_users WHERE workspace_id = $1`
	args := []any{workspaceID}

	if whereClause != "" {
		query += " AND " + whereClause
		args = append(args, filterArgs...)
	}

	sortCol := resolveUserSortColumn(sortAttr)
	direction := "ASC"
	if strings.EqualFold(sortDir, "descending") {
		direction = "DESC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s", sortCol, direction)
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	rows, err := jdbc.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*model.ScimUser
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func resolveUserSortColumn(sortBy string) string {
	switch strings.ToLower(sortBy) {
	case "username", "user_name":
		return "user_name"
	case "name.familyname":
		return "name_family_name"
	case "name.givenname":
		return "name_given_name"
	case "displayname":
		return "display_name"
	case "title":
		return "title"
	case "emails.value", "email":
		return "emails"
	case "meta.created":
		return "created_at"
	case "meta.lastmodified":
		return "last_modified"
	case "externalid":
		return "external_id"
	case "active":
		return "active"
	default:
		return "user_name"
	}
}

// Transactional variants
func (r *UserRepository) FindByIDAndWorkspaceIDTx(ctx context.Context, tx jdbc.Executor, id, workspaceID uuid.UUID) (*model.ScimUser, error) {
	query := `SELECT ` + userColumns + ` FROM scim_users WHERE id = $1 AND workspace_id = $2`
	row := tx.QueryRowContext(ctx, query, id, workspaceID)
	u, err := scanUser(row)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// JSON helpers

func unmarshalJSON[T any](data []byte) []T {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var result []T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

func marshalJSON(v any) []byte {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	if string(data) == "null" {
		return nil
	}
	return data
}

var ErrOptimisticLock = fmt.Errorf("optimistic lock conflict: resource was modified concurrently")
