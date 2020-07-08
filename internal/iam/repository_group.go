package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// CreateGroup will create a group in the repository and return the written
// group.  No options are currently supported.
func (r *Repository) CreateGroup(ctx context.Context, group *Group, opt ...Option) (*Group, error) {
	if group == nil {
		return nil, fmt.Errorf("create group: missing group %w", db.ErrNilParameter)
	}
	if group.Group == nil {
		return nil, fmt.Errorf("create group: missing group store %w", db.ErrNilParameter)
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
func (r *Repository) UpdateGroup(ctx context.Context, group *Group, fieldMaskPaths []string, opt ...Option) (*Group, int, error) {
	if group == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update group: missing group %w", db.ErrNilParameter)
	}
	if group.Group == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update group: missing group store %w", db.ErrNilParameter)
	}
	if group.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update group: missing group public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update group: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = buildUpdatePaths(
		map[string]interface{}{
			"name":        group.Name,
			"description": group.Description,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update group: %w", db.ErrEmptyFieldMask)
	}
	g := group.Clone().(*Group)
	resource, rowsUpdated, err := r.update(ctx, g, dbMask, nullFields)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update group: group %s already exists in organization %s: %w", group.Name, group.ScopeId, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update group: %w for %s", err, group.PublicId)
	}
	return resource.(*Group), rowsUpdated, err
}

// LookupGroup will look up a group in the repository.  If the group is not
// found, it will return nil, nil.
func (r *Repository) LookupGroup(ctx context.Context, withPublicId string, opt ...Option) (*Group, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup group: missing public id %w", db.ErrNilParameter)
	}
	g := allocGroup()
	g.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &g); err != nil {
		return nil, fmt.Errorf("lookup group: failed %w for %s", err, withPublicId)
	}
	return &g, nil
}

// DeleteGroup will delete a group from the repository.
func (r *Repository) DeleteGroup(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete group: missing public id %w", db.ErrNilParameter)
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
// error will be returned.  The users and group must all be in the same
// organization or the user must be in the project group's parent organization.
func (r *Repository) AddGroupMembers(ctx context.Context, groupId string, groupVersion int, userIds []string, opt ...Option) ([]*GroupMember, error) {

	if groupId == "" {
		return nil, fmt.Errorf("add group members: missing group id %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 {
		return nil, fmt.Errorf("add group members: missing user ids to add %w", db.ErrInvalidParameter)
	}

	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("add group members: unable to get group %s scope: %w", groupId, err)
	}

	newGroupMembers := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		gm, err := NewGroupMember(groupId, id)
		if err != nil {
			return nil, fmt.Errorf("add group members: unable to create in memory group member: %w", err)
		}
		newGroupMembers = append(newGroupMembers, gm)
	}

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
			updatedGroup.Version = uint32(groupVersion) + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(groupVersion))
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
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, groupTicket, metadata, msgs); err != nil {
				return fmt.Errorf("add group members: unable to write oplog: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("add group members: error adding members: %w", err)
	}
	members := make([]*GroupMember, 0, len(newGroupMembers)+len(newGroupMembers))
	for _, m := range newGroupMembers {
		members = append(members, m.(*GroupMember))
	}
	return members, nil
}

// DeleteGroupMembers (userIds) from a group (groupId). The group's current db version
// must match the groupVersion or an error will be returned.
func (r *Repository) DeleteGroupMembers(ctx context.Context, groupId string, groupVersion int, userIds []string, opt ...Option) (int, error) {
	if groupId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete group members: missing group id: %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete group members: missing either user or groups to delete %w", db.ErrInvalidParameter)
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete group members: unable to get group %s scope: %w", groupId, err)
	}

	deleteMembers := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		member, err := NewGroupMember(groupId, id)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("delete group members: unable to create in memory group member: %w", err)
		}
		deleteMembers = append(deleteMembers, member)
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
			updatedGroup.Version = uint32(groupVersion) + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(groupVersion))
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
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, groupTicket, metadata, msgs); err != nil {
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
// members will be cleared.
func (r *Repository) SetGroupMembers(ctx context.Context, groupId string, groupVersion int, userIds []string, opt ...Option) ([]*GroupMember, int, error) {
	// NOTE - we are intentionally not going to check that the scopes are
	// correct for the userIds, given the groupId.  We are going to
	// rely on the database constraints and triggers to maintain the integrity
	// of these scope relationships.  The users and group need to either be in
	// the same organization or the group needs to be in a project of the user's
	// org. There are constraints and triggers to enforce these relationships.
	if groupId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: missing role id: %w", db.ErrInvalidParameter)
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: unable to get role %s scope: %w", groupId, err)
	}

	// find existing members (since we're using groupVersion, we can safely do
	// this here, outside the TxHandler)
	members := []*GroupMember{}
	if err := r.reader.SearchWhere(ctx, &members, "group_id = ?", []interface{}{groupId}); err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: unable to search for existing members of group %s: %w", groupId, err)
	}
	found := map[string]*GroupMember{}
	for _, m := range members {
		found[m.GroupId+m.MemberId] = m
	}
	currentMembers := make([]*GroupMember, 0, len(userIds)+len(found))
	addMembers := make([]interface{}, 0, len(userIds))
	deleteMembers := make([]interface{}, 0, len(userIds))

	for _, usrId := range userIds {
		m, ok := found[groupId+usrId]
		if ok {
			// we have a match, so do nada since we want to keep it, but remove
			// it from found.
			currentMembers = append(currentMembers, m)
			delete(found, groupId+usrId)
			continue
		}
		// not found, so we add it
		gm, err := NewGroupMember(groupId, usrId)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("add group members: unable to create in memory group member: %w", err)
		}
		addMembers = append(addMembers, gm)
		currentMembers = append(currentMembers, gm)
	}
	if len(found) > 0 {
		for _, gm := range found {
			deleteMembers = append(deleteMembers, gm)
		}
	}

	// handle no change to existing group members
	if len(addMembers) == 0 && len(deleteMembers) == 0 {
		return currentMembers, db.NoRowsAffected, nil
	}

	var totalRowsAffected int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
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
			updatedGroup.Version = uint32(groupVersion) + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(groupVersion))
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
					return fmt.Errorf("set group members: unable to delete user roles: %w", err)
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
			// we're done with all the principal writes, so let's write the
			// role's update oplog message
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, groupTicket, metadata, msgs); err != nil {
				return fmt.Errorf("set group members: unable to write oplog for additions: %w", err)
			}

			currentMembers, err = r.ListGroupMembers(ctx, groupId)
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
