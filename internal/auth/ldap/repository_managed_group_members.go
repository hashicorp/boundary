// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// managedGroupMemberAccountTableName defines the default table name for a Managed Group
const managedGroupMemberAccountTableName = "auth_ldap_managed_group_member_account"

// ManagedGroupMemberAccount contains a mapping between a managed group and a
// member account.
type ManagedGroupMemberAccount struct {
	*store.ManagedGroupMemberAccount
	tableName string
}

// TableName returns the table name.
func (mg *ManagedGroupMemberAccount) TableName() string {
	if mg.tableName != "" {
		return mg.tableName
	}
	return managedGroupMemberAccountTableName
}

// SetTableName sets the table name.
func (mg *ManagedGroupMemberAccount) SetTableName(n string) {
	mg.tableName = n
}

// ListManagedGroupMembershipsByMember lists managed group memberships via the
// member (account) ID and supports WithLimit option.
func (r *Repository) ListManagedGroupMembershipsByMember(ctx context.Context, withAcctId string, opt ...Option) ([]*ManagedGroupMemberAccount, error) {
	const op = "ldap.(Repository).ListManagedGroupMembershipsByMember"
	if withAcctId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account id")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var mgs []*ManagedGroupMemberAccount
	err = r.reader.SearchWhere(ctx, &mgs, "member_id = ?", []any{withAcctId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return mgs, nil
}

// ListManagedGroupMembershipsByGroup lists managed group memberships via the
// group ID and supports WithLimit option.
func (r *Repository) ListManagedGroupMembershipsByGroup(ctx context.Context, withGroupId string, opt ...Option) ([]*ManagedGroupMemberAccount, error) {
	const op = "ldap.(Repository).ListManagedGroupMembershipsByGroup"
	if withGroupId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing managed group id")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var mgs []*ManagedGroupMemberAccount
	err = r.reader.SearchWhere(ctx, &mgs, "managed_group_id = ?", []any{withGroupId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return mgs, nil
}
