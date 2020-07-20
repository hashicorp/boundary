package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

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
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, groupTicket, metadata, msgs); err != nil {
				return fmt.Errorf("add group members: unable to write oplog: %w", err)
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := Repository{
				reader:  reader,
				writer:  w,
				wrapper: r.wrapper,
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

	// find existing members (since we're using groupVersion, we can safely do
	// this here, outside the TxHandler)
	currentMembers := []*GroupMember{}
	if err := r.reader.SearchWhere(ctx, &currentMembers, "group_id = ?", []interface{}{groupId}); err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set group members: unable to search for existing members of group %s: %w", groupId, err)
	}
	found := map[string]*GroupMember{}
	for _, m := range currentMembers {
		found[m.GroupId+m.MemberId] = m
	}
	addMembers := make([]interface{}, 0, len(userIds))
	deleteMembers := make([]interface{}, 0, len(userIds))

	for _, usrId := range userIds {
		_, ok := found[groupId+usrId]
		if ok {
			// we have a match, so do nada since we want to keep it, but remove
			// it from found.
			delete(found, groupId+usrId)
			continue
		}
		// not found, so we add it
		gm, err := NewGroupMemberUser(groupId, usrId)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set group members: unable to create in memory group member: %w", err)
		}
		addMembers = append(addMembers, gm)
	}
	if len(found) > 0 {
		for _, fgm := range found {
			// not found, so we add it
			gm, err := NewGroupMemberUser(fgm.GroupId, fgm.MemberId)
			if err != nil {
				return nil, db.NoRowsAffected, fmt.Errorf("set group members: unable to create in memory group member: %w", err)
			}
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
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, groupTicket, metadata, msgs); err != nil {
				return fmt.Errorf("set group members: unable to write oplog for additions: %w", err)
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := Repository{
				reader:  reader,
				writer:  w,
				wrapper: r.wrapper,
				// intentionally not setting the defaultLimit, so we'll get all
				// the members without a limit
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
