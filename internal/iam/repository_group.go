package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateGroup will create a group in the repository and return the written
// group.  No options are currently supported.
func (r *Repository) CreateGroup(ctx context.Context, group *Group, opt ...Option) (*Group, error) {
	if group == nil {
		return nil, fmt.Errorf("create group: missing group %w", db.ErrInvalidParameter)
	}
	if group.Group == nil {
		return nil, fmt.Errorf("create group: missing group store %w", db.ErrInvalidParameter)
	}
	if group.PublicId != "" {
		return nil, fmt.Errorf("create group: public id not empty: %w", db.ErrInvalidParameter)
	}
	if group.ScopeId == "" {
		return nil, fmt.Errorf("create group: missing group scope id: %w", db.ErrInvalidParameter)
	}
	id, err := newGroupId()
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	g := group.Clone().(*Group)
	g.PublicId = id
	resource, err := r.create(ctx, g)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create group: group %s already exists in scope %s: %w", group.Name, group.ScopeId, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create group: %w for %s", err, g.PublicId)
	}
	return resource.(*Group), err
}

// UpdateGroup will update a group in the repository and return the written
// group. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// If no updatable fields are included in the fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateGroup(ctx context.Context, group *Group, version uint32, fieldMaskPaths []string, opt ...Option) (*Group, []*GroupMember, int, error) {
	if group == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update group: missing group %w", db.ErrInvalidParameter)
	}
	if group.Group == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update group: missing group store %w", db.ErrInvalidParameter)
	}
	if group.PublicId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update group: missing group public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update group: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"name":        group.Name,
			"description": group.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update group: %w", db.ErrEmptyFieldMask)
	}
	var resource Resource
	var rowsUpdated int
	var members []*GroupMember
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			g := group.Clone().(*Group)
			resource, rowsUpdated, err = r.update(ctx, g, version, dbMask, nullFields)
			if err != nil {
				return err
			}
			repo, err := NewRepository(read, w, r.kms)
			if err != nil {
				return fmt.Errorf("update group: failed creating inner repo: %w for %s", err, group.PublicId)
			}
			members, err = repo.ListGroupMembers(ctx, group.PublicId)
			if err != nil {
				return fmt.Errorf("update group: listing group members: %w for %s", err, group.PublicId)
			}
			return nil
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update group: group %s already exists in org %s: %w", group.Name, group.ScopeId, db.ErrNotUnique)
		}
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update group: %w for %s", err, group.PublicId)
	}
	return resource.(*Group), members, rowsUpdated, err
}

// LookupGroup will look up a group in the repository.  If the group is not
// found, it will return nil, nil.
func (r *Repository) LookupGroup(ctx context.Context, withPublicId string, opt ...Option) (*Group, []*GroupMember, error) {
	if withPublicId == "" {
		return nil, nil, fmt.Errorf("lookup group: missing public id %w", db.ErrInvalidParameter)
	}
	g := allocGroup()
	g.PublicId = withPublicId
	var members []*GroupMember
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupByPublicId(ctx, &g); err != nil {
				return fmt.Errorf("lookup group: failed %w for %s", err, withPublicId)
			}
			repo, err := NewRepository(read, w, r.kms)
			if err != nil {
				return fmt.Errorf("lookup group: failed creating inner repo: %w for %s", err, withPublicId)
			}
			members, err = repo.ListGroupMembers(ctx, withPublicId)
			if err != nil {
				return fmt.Errorf("lookup group: listing group members: %w for %s", err, withPublicId)
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("lookup group: failed %w for %s", err, withPublicId)
	}
	return &g, members, nil
}

// DeleteGroup will delete a group from the repository.
func (r *Repository) DeleteGroup(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete group: missing public id %w", db.ErrInvalidParameter)
	}
	g := allocGroup()
	g.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &g); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete group: failed %w for %s", err, withPublicId)
	}
	rowsDeleted, err := r.delete(ctx, &g)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete group: failed %w for %s", err, withPublicId)
	}
	return rowsDeleted, nil
}

// ListGroups in a scope and supports WithLimit option.
func (r *Repository) ListGroups(ctx context.Context, withScopeId string, opt ...Option) ([]*Group, error) {
	if withScopeId == "" {
		return nil, fmt.Errorf("list groups: missing scope id %w", db.ErrInvalidParameter)
	}
	var grps []*Group
	err := r.list(ctx, &grps, "scope_id = ?", []interface{}{withScopeId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	return grps, nil
}

// ListGroupMembers of a group and supports WithLimit option.
func (r *Repository) ListGroupMembers(ctx context.Context, withGroupId string, opt ...Option) ([]*GroupMember, error) {
	if withGroupId == "" {
		return nil, fmt.Errorf("list group members: missing group id: %w", db.ErrInvalidParameter)
	}
	members := []*GroupMember{}
	if err := r.list(ctx, &members, "group_id = ?", []interface{}{withGroupId}, opt...); err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	return members, nil
}

// AddGroupMembers provides the ability to add members (userIds) to a group
// (groupId).  The group's current db version must match the groupVersion or an
// error will be returned.  Zero is not a valid value for the WithVersion option
// and will return an error.
func (r *Repository) AddGroupMembers(ctx context.Context, groupId string, groupVersion uint32, userIds []string, opt ...Option) ([]*GroupMember, error) {
	if groupId == "" {
		return nil, fmt.Errorf("add group members: missing group id %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 {
		return nil, fmt.Errorf("add group members: missing user ids to add %w", db.ErrInvalidParameter)
	}
	if groupVersion == 0 {
		return nil, fmt.Errorf("add group members: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("add group members: unable to get group %s scope: %w", groupId, err)
	}

	newGroupMembers := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		gm, err := NewGroupMemberUser(groupId, id)
		if err != nil {
			return nil, fmt.Errorf("add group members: unable to create in memory group member: %w", err)
		}
		newGroupMembers = append(newGroupMembers, gm)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("add group members: unable to get oplog wrapper: %w", err)
	}

	var currentMembers []*GroupMember
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			groupTicket, err := w.GetTicket(&group)
			if err != nil {
				return fmt.Errorf("add group members: unable to get ticket: %w", err)
			}
			updatedGroup := allocGroup()
			updatedGroup.PublicId = groupId
			updatedGroup.Version = groupVersion + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(&groupVersion))
			if err != nil {
				return fmt.Errorf("add group members: unable to update group version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("add group members: updated group and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &groupOplogMsg)
			memberOplogMsgs := make([]*oplog.Message, 0, len(newGroupMembers))
			if err := w.CreateItems(ctx, newGroupMembers, db.NewOplogMsgs(&memberOplogMsgs)); err != nil {
				return fmt.Errorf("add group members: unable to add users: %w", err)
			}
			msgs = append(msgs, memberOplogMsgs...)
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{groupId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, groupTicket, metadata, msgs); err != nil {
				return fmt.Errorf("add group members: unable to write oplog: %w", err)
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the members without a limit
			}
			currentMembers, err = txRepo.ListGroupMembers(ctx, groupId)
			if err != nil {
				return fmt.Errorf("set group members: unable to retrieve current group members after sets: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("add group members: error adding members: %w", err)
	}
	return currentMembers, nil
}

// DeleteGroupMembers (userIds) from a group (groupId). The group's current db version
// must match the groupVersion or an error will be returned. Zero is not a valid
// value for the WithVersion option and will return an error.
func (r *Repository) DeleteGroupMembers(ctx context.Context, groupId string, groupVersion uint32, userIds []string, opt ...Option) (int, error) {
	if groupId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete group members: missing group id: %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete group members: missing either user or groups to delete %w", db.ErrInvalidParameter)
	}
	if groupVersion == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete group members: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete group members: unable to get group %s scope: %w", groupId, err)
	}

	deleteMembers := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		member, err := NewGroupMemberUser(groupId, id)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("delete group members: unable to create in memory group member: %w", err)
		}
		deleteMembers = append(deleteMembers, member)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("add group members: unable to get oplog wrapper: %w", err)
	}

	var totalRowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			groupTicket, err := w.GetTicket(&group)
			if err != nil {
				return fmt.Errorf("delete group members: unable to get ticket: %w", err)
			}
			updatedGroup := allocGroup()
			updatedGroup.PublicId = groupId
			updatedGroup.Version = groupVersion + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(&groupVersion))
			if err != nil {
				return fmt.Errorf("delete group members: unable to update group version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("delete group members: updated group and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &groupOplogMsg)
			userOplogMsgs := make([]*oplog.Message, 0, len(deleteMembers))
			rowsDeleted, err := w.DeleteItems(ctx, deleteMembers, db.NewOplogMsgs(&userOplogMsgs))
			if err != nil {
				return fmt.Errorf("delete group members: unable to delete group members: %w", err)
			}
			if rowsDeleted != len(deleteMembers) {
				return fmt.Errorf("delete group members: group members deleted %d did not match request for %d", rowsDeleted, len(deleteMembers))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, userOplogMsgs...)
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{groupId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, groupTicket, metadata, msgs); err != nil {
				return fmt.Errorf("delete group members: unable to write oplog: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete group members: error deleting members: %w", err)
	}
	return totalRowsDeleted, nil
}

// SetGroupMembers will set the group's members.  If userIds is empty, the
// members will be cleared. Zero is not a valid value for the WithVersion option
// and will return an error.
func (r *Repository) SetGroupMembers(ctx context.Context, groupId string, groupVersion uint32, userIds []string, opt ...Option) ([]*GroupMember, int, error) {
	if groupId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: missing group id: %w", db.ErrInvalidParameter)
	}
	if groupVersion == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: unable to get members %s scope: %w", groupId, err)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("add group members: unable to get oplog wrapper: %w", err)
	}

	var currentMembers []*GroupMember
	var totalRowsAffected int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the members without a limit
			}
			addMembers, deleteMembers, err := groupMemberChanges(ctx, reader, groupId, userIds)
			if err != nil {
				return fmt.Errorf("set associated accounts: unable to determine changes: %w", err)
			}
			// handle no change to existing group members
			if len(addMembers) == 0 && len(deleteMembers) == 0 {
				currentMembers, err = txRepo.ListGroupMembers(ctx, groupId)
				if err != nil {
					return fmt.Errorf("set group members: unable to retrieve current group members after sets: %w", err)
				}
				return nil
			}

			msgs := make([]*oplog.Message, 0, 2)
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{groupId},
			}
			// we need a group, which won't be redeemed until all the other
			// writes are successful.  We can't just use a single ticket because
			// we need to write oplog entries for deletes and adds
			groupTicket, err := w.GetTicket(&group)
			if err != nil {
				return fmt.Errorf("set group members: unable to get ticket for group: %w", err)
			}
			updatedGroup := allocGroup()
			updatedGroup.PublicId = groupId
			updatedGroup.Version = groupVersion + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(&groupVersion))
			if err != nil {
				return fmt.Errorf("set group members: unable to update group version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("set group members: updated group and %d rows updated", rowsUpdated)
			}
			if len(deleteMembers) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(deleteMembers))
				rowsDeleted, err := w.DeleteItems(ctx, deleteMembers, db.NewOplogMsgs(&userOplogMsgs))
				if err != nil {
					return fmt.Errorf("set group members: unable to delete group member: %w", err)
				}
				if rowsDeleted != len(deleteMembers) {
					return fmt.Errorf("set group members: members deleted %d did not match request for %d", rowsDeleted, len(deleteMembers))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, userOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}
			if len(addMembers) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(addMembers))
				if err := w.CreateItems(ctx, addMembers, db.NewOplogMsgs(&userOplogMsgs)); err != nil {
					return fmt.Errorf("set group members: unable to add users: %w", err)
				}
				totalRowsAffected += len(addMembers)
				msgs = append(msgs, userOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())

			}
			// we're done with all the membership writes, so let's write the
			// group's update oplog message
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, groupTicket, metadata, msgs); err != nil {
				return fmt.Errorf("set group members: unable to write oplog for additions: %w", err)
			}
			currentMembers, err = txRepo.ListGroupMembers(ctx, groupId)
			if err != nil {
				return fmt.Errorf("set group members: unable to retrieve current group members after sets: %w", err)
			}
			return nil
		})
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: unable to set group members: %w", err)
	}
	return currentMembers, totalRowsAffected, nil
}

// groupMemberChanges returns two slices: members to add and delete
func groupMemberChanges(ctx context.Context, reader db.Reader, groupId string, userIds []string) ([]interface{}, []interface{}, error) {
	var inClauseSpots []string
	// starts at 2 because there is already a $1 in the query
	for i := 2; i < len(userIds)+2; i++ {
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("$%d", i))
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}
	query := fmt.Sprintf(grpMemberChangesQuery, inClause)

	var params []interface{}
	params = append(params, groupId)
	for _, v := range userIds {
		params = append(params, v)
	}
	// fmt.Println(query, params)
	rows, err := reader.Query(query, params)
	if err != nil {
		return nil, nil, fmt.Errorf("changes: query failed: %w", err)
	}
	defer rows.Close()

	type change struct {
		Action   string
		MemberId string
	}
	var changes []*change
	for rows.Next() {
		var chg change
		if err := reader.ScanRows(rows, &chg); err != nil {
			return nil, nil, fmt.Errorf("changes: scan row failed: %w", err)
		}
		changes = append(changes, &chg)
	}
	addMembers := []interface{}{}
	deleteMembers := []interface{}{}
	for _, c := range changes {
		if c.MemberId == "" {
			return nil, nil, fmt.Errorf("changes: missing user id in change result")
		}
		switch c.Action {
		case "add":
			gm, err := NewGroupMemberUser(groupId, c.MemberId)
			if err != nil {
				return nil, nil, fmt.Errorf("set group members: unable to create in memory group member for add: %w", err)
			}
			addMembers = append(addMembers, gm)
		case "delete":
			gm, err := NewGroupMemberUser(groupId, c.MemberId)
			if err != nil {
				return nil, nil, fmt.Errorf("set group members: unable to create in memory group member for delete: %w", err)
			}
			deleteMembers = append(deleteMembers, gm)
		default:
			return nil, nil, fmt.Errorf("changes: unknown action %s for %s", c.Action, c.MemberId)
		}

	}
	return addMembers, deleteMembers, nil
}
