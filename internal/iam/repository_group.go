// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
)

// CreateGroup will create a group in the repository and return the written
// group.  No options are currently supported.
func (r *Repository) CreateGroup(ctx context.Context, group *Group, _ ...Option) (*Group, error) {
	const op = "iam.(Repository).CreateGroup"
	if group == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing group")
	}
	if group.Group == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing group store")
	}
	if group.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if group.ScopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	id, err := newGroupId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	g := group.Clone().(*Group)
	g.PublicId = id
	resource, err := r.create(ctx, g)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("group %s already exists in scope %s", group.Name, group.ScopeId))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for group %s", g.PublicId)))
	}
	return resource.(*Group), nil
}

// UpdateGroup will update a group in the repository and return the written
// group. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// If no updatable fields are included in the fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateGroup(ctx context.Context, group *Group, version uint32, fieldMaskPaths []string, _ ...Option) (*Group, []*GroupMember, int, error) {
	const op = "iam.(Repository).UpdateGroup"
	if group == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing group")
	}
	if group.Group == nil {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing group store")
	}
	if group.PublicId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"name":        group.Name,
			"description": group.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
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
				return errors.Wrap(ctx, err, op)
			}
			repo, err := NewRepository(ctx, read, w, r.kms)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			members, err = repo.ListGroupMembers(ctx, group.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("group %s already exists in scope %s", group.Name, group.ScopeId))
		}
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for group %s", group.PublicId)))
	}
	return resource.(*Group), members, rowsUpdated, nil
}

// LookupGroup will look up a group in the repository.  If the group is not
// found, it will return nil, nil.
func (r *Repository) LookupGroup(ctx context.Context, withPublicId string, _ ...Option) (*Group, []*GroupMember, error) {
	const op = "iam.(Repository).LookupGroup"
	if withPublicId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
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
				return errors.Wrap(ctx, err, op)
			}
			repo, err := NewRepository(ctx, read, w, r.kms)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			members, err = repo.ListGroupMembers(ctx, withPublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for group %s", withPublicId)))
	}
	return &g, members, nil
}

// DeleteGroup will delete a group from the repository.
func (r *Repository) DeleteGroup(ctx context.Context, withPublicId string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteGroup"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	g := allocGroup()
	g.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &g); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for group %s", withPublicId)))
	}
	rowsDeleted, err := r.delete(ctx, &g)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for group %s", withPublicId)))
	}
	return rowsDeleted, nil
}

// ListGroups lists groups in the given scopes and supports WithLimit option.
func (r *Repository) ListGroups(ctx context.Context, withScopeIds []string, opt ...Option) ([]*Group, error) {
	const op = "iam.(Repository).ListGroups"
	if len(withScopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	var grps []*Group
	err := r.list(ctx, &grps, "scope_id in (?)", []any{withScopeIds}, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return grps, nil
}

// ListGroupMembers of a group and supports WithLimit option.
func (r *Repository) ListGroupMembers(ctx context.Context, withGroupId string, opt ...Option) ([]*GroupMember, error) {
	const op = "iam.(Repository).ListGroupMembers"
	if withGroupId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing group id")
	}
	members := []*GroupMember{}
	if err := r.list(ctx, &members, "group_id = ?", []any{withGroupId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return members, nil
}

// AddGroupMembers provides the ability to add members (userIds) to a group
// (groupId).  The group's current db version must match the groupVersion or an
// error will be returned.  Zero is not a valid value for the WithVersion option
// and will return an error.
func (r *Repository) AddGroupMembers(ctx context.Context, groupId string, groupVersion uint32, userIds []string, _ ...Option) ([]*GroupMember, error) {
	const op = "iam.(Repository).AddGroupMembers"
	if groupId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing group id")
	}
	if len(userIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user ids")
	}
	if groupVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get group members %s scope", groupId)))
	}

	newGroupMembers := make([]any, 0, len(userIds))
	for _, id := range userIds {
		gm, err := NewGroupMemberUser(ctx, groupId, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group member"))
		}
		newGroupMembers = append(newGroupMembers, gm)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var currentMembers []*GroupMember
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			groupTicket, err := w.GetTicket(ctx, &group)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedGroup := allocGroup()
			updatedGroup.PublicId = groupId
			updatedGroup.Version = groupVersion + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(&groupVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update group version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated group and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &groupOplogMsg)
			memberOplogMsgs := make([]*oplog.Message, 0, len(newGroupMembers))
			if err := w.CreateItems(ctx, newGroupMembers, db.NewOplogMsgs(&memberOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add users"))
			}
			msgs = append(msgs, memberOplogMsgs...)
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{groupId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, groupTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
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
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current group members after sets"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return currentMembers, nil
}

// DeleteGroupMembers (userIds) from a group (groupId). The group's current db version
// must match the groupVersion or an error will be returned. Zero is not a valid
// value for the WithVersion option and will return an error.
func (r *Repository) DeleteGroupMembers(ctx context.Context, groupId string, groupVersion uint32, userIds []string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteGroupMembers"
	if groupId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing group id")
	}
	if len(userIds) == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing either user or groups to delete")
	}
	if groupVersion == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get group members %s scope", groupId)))
	}

	deleteMembers := make([]any, 0, len(userIds))
	for _, id := range userIds {
		member, err := NewGroupMemberUser(ctx, groupId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group member"))
		}
		deleteMembers = append(deleteMembers, member)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			groupTicket, err := w.GetTicket(ctx, &group)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedGroup := allocGroup()
			updatedGroup.PublicId = groupId
			updatedGroup.Version = groupVersion + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(&groupVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update group version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated group and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &groupOplogMsg)
			userOplogMsgs := make([]*oplog.Message, 0, len(deleteMembers))
			rowsDeleted, err := w.DeleteItems(ctx, deleteMembers, db.NewOplogMsgs(&userOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete group members"))
			}
			if rowsDeleted != len(deleteMembers) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("group members deleted %d did not match request for %d", rowsDeleted, len(deleteMembers)))
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
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return totalRowsDeleted, nil
}

// SetGroupMembers will set the group's members.  If userIds is empty, the
// members will be cleared. Zero is not a valid value for the WithVersion option
// and will return an error.
func (r *Repository) SetGroupMembers(ctx context.Context, groupId string, groupVersion uint32, userIds []string, _ ...Option) ([]*GroupMember, int, error) {
	const op = "iam.(Repository).SetGroupMembers"
	if groupId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing group id")
	}
	if groupVersion == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	group := allocGroup()
	group.PublicId = groupId
	scope, err := group.GetScope(ctx, r.reader)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get group members %s scope", groupId)))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
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
				return errors.Wrap(ctx, err, op)
			}
			// handle no change to existing group members
			if len(addMembers) == 0 && len(deleteMembers) == 0 {
				currentMembers, err = txRepo.ListGroupMembers(ctx, groupId)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current group members after sets"))
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
			groupTicket, err := w.GetTicket(ctx, &group)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedGroup := allocGroup()
			updatedGroup.PublicId = groupId
			updatedGroup.Version = groupVersion + 1
			var groupOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedGroup, []string{"Version"}, nil, db.NewOplogMsg(&groupOplogMsg), db.WithVersion(&groupVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update group verison"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated group and %d rows updated", rowsUpdated))
			}
			if len(deleteMembers) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(deleteMembers))
				rowsDeleted, err := w.DeleteItems(ctx, deleteMembers, db.NewOplogMsgs(&userOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete group member"))
				}
				if rowsDeleted != len(deleteMembers) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("members deleted %d did not match request for %d", rowsDeleted, len(deleteMembers)))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, userOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}
			if len(addMembers) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(addMembers))
				if err := w.CreateItems(ctx, addMembers, db.NewOplogMsgs(&userOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add users"))
				}
				totalRowsAffected += len(addMembers)
				msgs = append(msgs, userOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())

			}
			// we're done with all the membership writes, so let's write the
			// group's update oplog message
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, groupTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			currentMembers, err = txRepo.ListGroupMembers(ctx, groupId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current group members after set"))
			}
			return nil
		})
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return currentMembers, totalRowsAffected, nil
}

// groupMemberChanges returns two slices: members to add and delete
func groupMemberChanges(ctx context.Context, reader db.Reader, groupId string, userIds []string) ([]any, []any, error) {
	const op = "iam.groupMemberChanges"
	var inClauseSpots []string
	// starts at 2 because there is already a ? in the query
	for i := 2; i < len(userIds)+2; i++ {
		inClauseSpots = append(inClauseSpots, "?")
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}
	query := fmt.Sprintf(grpMemberChangesQuery, inClause)

	var params []any
	for _, v := range userIds {
		params = append(params, v)
	}
	params = append(params, groupId)

	rows, err := reader.Query(ctx, query, params)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	type change struct {
		Action   string
		MemberId string
	}
	var changes []*change
	for rows.Next() {
		var chg change
		if err := reader.ScanRows(ctx, rows, &chg); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		changes = append(changes, &chg)
	}
	addMembers := []any{}
	deleteMembers := []any{}
	for _, c := range changes {
		if c.MemberId == "" {
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id in change result")
		}
		switch c.Action {
		case "add":
			gm, err := NewGroupMemberUser(ctx, groupId, c.MemberId)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group member for add"))
			}
			addMembers = append(addMembers, gm)
		case "delete":
			gm, err := NewGroupMemberUser(ctx, groupId, c.MemberId)
			if err != nil {
				return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group member for delete"))
			}
			deleteMembers = append(deleteMembers, gm)
		default:
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown action %s for %s", c.Action, c.MemberId))
		}

	}
	return addMembers, deleteMembers, nil
}
