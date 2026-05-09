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

type GroupRepository struct{}

func NewGroupRepository() *GroupRepository {
	return &GroupRepository{}
}

var groupColumns = `id, workspace_id, external_id, display_name, created_at, last_modified, version`

func scanGroup(row rowScanner) (*model.ScimGroup, error) {
	var g model.ScimGroup
	err := row.Scan(&g.ID, &g.WorkspaceID, &g.ExternalID, &g.DisplayName,
		&g.CreatedAt, &g.LastModified, &g.Version)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (r *GroupRepository) FindByIDAndWorkspaceID(ctx context.Context, id, workspaceID uuid.UUID) (*model.ScimGroup, error) {
	query := `SELECT ` + groupColumns + ` FROM scim_groups WHERE id = $1 AND workspace_id = $2`
	row := jdbc.QueryRowContext(ctx, query, id, workspaceID)
	g, err := scanGroup(row)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

func (r *GroupRepository) FindByDisplayNameAndWorkspaceID(ctx context.Context, displayName string, workspaceID uuid.UUID) (*model.ScimGroup, error) {
	query := `SELECT ` + groupColumns + ` FROM scim_groups WHERE display_name = $1 AND workspace_id = $2`
	row := jdbc.QueryRowContext(ctx, query, displayName, workspaceID)
	g, err := scanGroup(row)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

// Deprecated: Pool method
func (r *GroupRepository) Pool() any {
	return nil
}

func (r *GroupRepository) Create(ctx context.Context, g *model.ScimGroup) error {
	g.ID = uuid.New()
	now := time.Now().UTC()
	g.CreatedAt = now
	g.LastModified = now
	g.Version = 0

	_, err := jdbc.ExecContext(ctx,
		`INSERT INTO scim_groups (id, workspace_id, external_id, display_name, created_at, last_modified, version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		g.ID, g.WorkspaceID, g.ExternalID, g.DisplayName, g.CreatedAt, g.LastModified, g.Version)
	return err
}

func (r *GroupRepository) Update(ctx context.Context, g *model.ScimGroup) error {
	g.LastModified = time.Now().UTC()
	oldVersion := g.Version
	g.Version++

	tag, err := jdbc.ExecContext(ctx,
		`UPDATE scim_groups SET external_id=$1, display_name=$2, last_modified=$3, version=$4
		 WHERE id=$5 AND version=$6`,
		g.ExternalID, g.DisplayName, g.LastModified, g.Version, g.ID, oldVersion)
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

func (r *GroupRepository) Delete(ctx context.Context, id, workspaceID uuid.UUID) error {
	_, err := jdbc.ExecContext(ctx,
		`DELETE FROM scim_groups WHERE id = $1 AND workspace_id = $2`, id, workspaceID)
	return err
}

func (r *GroupRepository) Count(ctx context.Context, workspaceID uuid.UUID, whereClause string, args []any) (int64, error) {
	query := `SELECT COUNT(*) FROM scim_groups WHERE workspace_id = $1`
	queryArgs := []any{workspaceID}
	if whereClause != "" {
		query += " AND " + whereClause
		queryArgs = append(queryArgs, args...)
	}
	var count int64
	err := jdbc.QueryRowContext(ctx, query, queryArgs...).Scan(&count)
	return count, err
}

func (r *GroupRepository) List(ctx context.Context, workspaceID uuid.UUID, whereClause string, filterArgs []any,
	sortAttr, sortDir string, offset, limit int) ([]*model.ScimGroup, error) {

	query := `SELECT ` + groupColumns + ` FROM scim_groups WHERE workspace_id = $1`
	args := []any{workspaceID}
	if whereClause != "" {
		query += " AND " + whereClause
		args = append(args, filterArgs...)
	}

	sortCol := resolveGroupSortColumn(sortAttr)
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

	var groups []*model.ScimGroup
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func resolveGroupSortColumn(sortBy string) string {
	switch strings.ToLower(sortBy) {
	case "displayname", "display_name":
		return "display_name"
	case "meta.created":
		return "created_at"
	case "meta.lastmodified":
		return "last_modified"
	case "externalid":
		return "external_id"
	default:
		return "display_name"
	}
}

// --- Transactional variants (accept a Querier) ---

func (r *GroupRepository) FindByIDAndWorkspaceIDTx(ctx context.Context, tx jdbc.Executor, id, workspaceID uuid.UUID) (*model.ScimGroup, error) {
	query := `SELECT ` + groupColumns + ` FROM scim_groups WHERE id = $1 AND workspace_id = $2`
	row := tx.QueryRowContext(ctx, query, id, workspaceID)
	g, err := scanGroup(row)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

func (r *GroupRepository) FindByDisplayNameAndWorkspaceIDTx(ctx context.Context, tx jdbc.Executor, displayName string, workspaceID uuid.UUID) (*model.ScimGroup, error) {
	query := `SELECT ` + groupColumns + ` FROM scim_groups WHERE display_name = $1 AND workspace_id = $2`
	row := tx.QueryRowContext(ctx, query, displayName, workspaceID)
	g, err := scanGroup(row)
	if errors.Is(err, jdbc.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

func (r *GroupRepository) UpdateTx(ctx context.Context, tx jdbc.Executor, g *model.ScimGroup) error {
	g.LastModified = time.Now().UTC()
	oldVersion := g.Version
	g.Version++

	tag, err := tx.ExecContext(ctx,
		`UPDATE scim_groups SET external_id=$1, display_name=$2, last_modified=$3, version=$4
		 WHERE id=$5 AND version=$6`,
		g.ExternalID, g.DisplayName, g.LastModified, g.Version, g.ID, oldVersion)
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

// MembershipRepository

type MembershipRepository struct{}

func NewMembershipRepository() *MembershipRepository {
	return &MembershipRepository{}
}

func (r *MembershipRepository) FindByGroupID(ctx context.Context, groupID uuid.UUID) ([]model.ScimGroupMembership, error) {
	rows, err := jdbc.QueryContext(ctx,
		`SELECT id, group_id, workspace_id, member_value, member_type, display
		 FROM scim_group_memberships WHERE group_id = $1`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMemberships(rows)
}

func (r *MembershipRepository) FindByGroupIDIn(ctx context.Context, groupIDs []uuid.UUID) ([]model.ScimGroupMembership, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(groupIDs))
	args := make([]any, len(groupIDs))
	for i, id := range groupIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(
		`SELECT id, group_id, workspace_id, member_value, member_type, display
		 FROM scim_group_memberships WHERE group_id IN (%s)`, strings.Join(placeholders, ","))

	rows, err := jdbc.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMemberships(rows)
}

func (r *MembershipRepository) FindByMemberValue(ctx context.Context, memberValue uuid.UUID) ([]model.ScimGroupMembership, error) {
	rows, err := jdbc.QueryContext(ctx,
		`SELECT m.id, m.group_id, m.workspace_id, m.member_value, m.member_type, m.display
		 FROM scim_group_memberships m WHERE m.member_value = $1`, memberValue)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMemberships(rows)
}

// FindByMemberValueWithGroup returns memberships with group info.
type MembershipWithGroup struct {
	Membership       model.ScimGroupMembership
	GroupDisplayName string
}

func (r *MembershipRepository) FindByMemberValueWithGroup(ctx context.Context, memberValue uuid.UUID) ([]MembershipWithGroup, error) {
	rows, err := jdbc.QueryContext(ctx,
		`SELECT m.id, m.group_id, m.workspace_id, m.member_value, m.member_type, m.display,
		        g.display_name
		 FROM scim_group_memberships m
		 JOIN scim_groups g ON g.id = m.group_id
		 WHERE m.member_value = $1`, memberValue)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MembershipWithGroup
	for rows.Next() {
		var mwg MembershipWithGroup
		err := rows.Scan(&mwg.Membership.ID, &mwg.Membership.GroupID, &mwg.Membership.WorkspaceID,
			&mwg.Membership.MemberValue, &mwg.Membership.MemberType, &mwg.Membership.Display,
			&mwg.GroupDisplayName)
		if err != nil {
			return nil, err
		}
		result = append(result, mwg)
	}
	return result, rows.Err()
}

func (r *MembershipRepository) FindByMemberValueInWithGroup(ctx context.Context, memberValues []uuid.UUID) ([]MembershipWithGroup, error) {
	if len(memberValues) == 0 {
		return nil, nil
	}
	// Build placeholder string
	placeholders := make([]string, len(memberValues))
	args := make([]any, len(memberValues))
	for i, v := range memberValues {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = v
	}

	query := fmt.Sprintf(
		`SELECT m.id, m.group_id, m.workspace_id, m.member_value, m.member_type, m.display,
		        g.display_name
		 FROM scim_group_memberships m
		 JOIN scim_groups g ON g.id = m.group_id
		 WHERE m.member_value IN (%s)`, strings.Join(placeholders, ","))

	rows, err := jdbc.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MembershipWithGroup
	for rows.Next() {
		var mwg MembershipWithGroup
		err := rows.Scan(&mwg.Membership.ID, &mwg.Membership.GroupID, &mwg.Membership.WorkspaceID,
			&mwg.Membership.MemberValue, &mwg.Membership.MemberType, &mwg.Membership.Display,
			&mwg.GroupDisplayName)
		if err != nil {
			return nil, err
		}
		result = append(result, mwg)
	}
	return result, rows.Err()
}

func (r *MembershipRepository) CreateBatch(ctx context.Context, memberships []model.ScimGroupMembership) error {
	if len(memberships) == 0 {
		return nil
	}
	for _, m := range memberships {
		_, err := jdbc.ExecContext(ctx,
			`INSERT INTO scim_group_memberships (id, group_id, workspace_id, member_value, member_type, display)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			m.ID, m.GroupID, m.WorkspaceID, m.MemberValue, m.MemberType, m.Display)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *MembershipRepository) DeleteByGroupID(ctx context.Context, groupID uuid.UUID) error {
	_, err := jdbc.ExecContext(ctx,
		`DELETE FROM scim_group_memberships WHERE group_id = $1`, groupID)
	return err
}

func (r *MembershipRepository) DeleteByMemberValue(ctx context.Context, memberValue uuid.UUID) error {
	_, err := jdbc.ExecContext(ctx,
		`DELETE FROM scim_group_memberships WHERE member_value = $1`, memberValue)
	return err
}

func (r *MembershipRepository) DeleteByGroupIDAndMemberValues(ctx context.Context, groupID uuid.UUID, memberValues []uuid.UUID) error {
	if len(memberValues) == 0 {
		return nil
	}
	placeholders := make([]string, len(memberValues))
	args := []any{groupID}
	for i, v := range memberValues {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, v)
	}
	query := fmt.Sprintf(`DELETE FROM scim_group_memberships WHERE group_id = $1 AND member_value IN (%s)`,
		strings.Join(placeholders, ","))
	_, err := jdbc.ExecContext(ctx, query, args...)
	return err
}

// Transactional variants for memberships

func (r *MembershipRepository) FindByGroupIDTx(ctx context.Context, tx jdbc.Executor, groupID uuid.UUID) ([]model.ScimGroupMembership, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, group_id, workspace_id, member_value, member_type, display
		 FROM scim_group_memberships WHERE group_id = $1`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMemberships(rows)
}

func (r *MembershipRepository) CreateBatchTx(ctx context.Context, tx jdbc.Executor, memberships []model.ScimGroupMembership) error {
	if len(memberships) == 0 {
		return nil
	}
	for _, m := range memberships {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO scim_group_memberships (id, group_id, workspace_id, member_value, member_type, display)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			m.ID, m.GroupID, m.WorkspaceID, m.MemberValue, m.MemberType, m.Display)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *MembershipRepository) DeleteByGroupIDTx(ctx context.Context, tx jdbc.Executor, groupID uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM scim_group_memberships WHERE group_id = $1`, groupID)
	return err
}

func (r *MembershipRepository) DeleteByMemberValueTx(ctx context.Context, tx jdbc.Executor, memberValue uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM scim_group_memberships WHERE member_value = $1`, memberValue)
	return err
}

func (r *MembershipRepository) DeleteByGroupIDAndMemberValuesTx(ctx context.Context, tx jdbc.Executor, groupID uuid.UUID, memberValues []uuid.UUID) error {
	if len(memberValues) == 0 {
		return nil
	}
	placeholders := make([]string, len(memberValues))
	args := []any{groupID}
	for i, v := range memberValues {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, v)
	}
	query := fmt.Sprintf(`DELETE FROM scim_group_memberships WHERE group_id = $1 AND member_value IN (%s)`,
		strings.Join(placeholders, ","))
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

func scanMemberships(rows jdbc.Rows) ([]model.ScimGroupMembership, error) {
	var result []model.ScimGroupMembership
	for rows.Next() {
		var m model.ScimGroupMembership
		err := rows.Scan(&m.ID, &m.GroupID, &m.WorkspaceID, &m.MemberValue, &m.MemberType, &m.Display)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// suppress unused import
var _ = json.Marshal
