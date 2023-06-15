// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/util"
)

// AddRoleGrantScope will add role grant scopes associated with the role ID in
// the repository. No options are currently supported. Zero is not a valid value
// for the WithVersion option and will return an error.
func (r *Repository) AddRoleGrantScopes(ctx context.Context, role *Role, grantScopes []string, _ ...Option) ([]*RoleGrantScope, error) {
	const op = "iam.(Repository).AddRoleGrantScopes"
	if util.IsNil(role) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil role")
	}
	if role.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if role.GetScopeId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role scope id")
	}
	if len(grantScopes) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grant scopes")
	}
	if role.Version == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	newRoleGrantScopes := make([]any, 0, len(grantScopes))
	for _, grantScope := range grantScopes {
		roleGrantScope, err := NewRoleGrantScope(ctx, role.GetPublicId(), grantScope)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant scope"))
		}
		newRoleGrantScopes = append(newRoleGrantScopes, roleGrantScope)
	}

	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope", role.PublicId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, role.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(ctx, role)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			// We need to update the role version as that's the aggregate
			updatedRole := allocRole()
			updatedRole.PublicId = role.GetPublicId()
			updatedRole.Version = uint32(role.Version + 1)
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&role.Version))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)
			roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(newRoleGrantScopes))
			if err := w.CreateItems(ctx, newRoleGrantScopes, db.NewOplogMsgs(&roleGrantScopesOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
			}
			msgs = append(msgs, roleGrantScopesOplogMsgs...)

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{role.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	roleGrantScopes := make([]*RoleGrantScope, 0, len(newRoleGrantScopes))
	for _, grantScope := range newRoleGrantScopes {
		roleGrantScopes = append(roleGrantScopes, grantScope.(*RoleGrantScope))
	}
	return roleGrantScopes, nil
}
