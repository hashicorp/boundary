// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

// defaultManagedGroupMemberAccountTableName defines the default table name for a Managed Group
const defaultManagedGroupMemberAccountTableName = "auth_oidc_managed_group_member_account"

// ManagedGroupMemberAccount contains a mapping between a managed group and a
// member account
type ManagedGroupMemberAccount struct {
	*store.ManagedGroupMemberAccount
	tableName string
}

// NewManagedGroupMemberAccount creates a new in memory
// ManagedGroupMemberAccount assigned to a managed group within an OIDC
// AuthMethod. Supported options are withName and withDescription.
func NewManagedGroupMemberAccount(ctx context.Context, managedGroupId string, memberId string, opt ...Option) (*ManagedGroupMemberAccount, error) {
	const op = "oidc.NewManagedGroupMemberAccount"
	mg := &ManagedGroupMemberAccount{
		ManagedGroupMemberAccount: &store.ManagedGroupMemberAccount{
			ManagedGroupId: managedGroupId,
			MemberId:       memberId,
		},
	}
	if err := mg.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped.
	}

	return mg, nil
}

// validate the ManagedGroupMemberAccount. On success, it will return nil.
func (mg *ManagedGroupMemberAccount) validate(ctx context.Context, caller errors.Op) error {
	if mg.ManagedGroupId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing managed group id")
	}
	if mg.MemberId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing member id")
	}

	return nil
}

// AllocManagedGroupMemberAccount makes an empty one in memory
func AllocManagedGroupMemberAccount() *ManagedGroupMemberAccount {
	return &ManagedGroupMemberAccount{
		ManagedGroupMemberAccount: &store.ManagedGroupMemberAccount{},
	}
}

// Clone a ManagedGroupMemberAccount.
func (mg *ManagedGroupMemberAccount) Clone() *ManagedGroupMemberAccount {
	cp := proto.Clone(mg.ManagedGroupMemberAccount)
	return &ManagedGroupMemberAccount{
		ManagedGroupMemberAccount: cp.(*store.ManagedGroupMemberAccount),
	}
}

// TableName returns the table name.
func (mg *ManagedGroupMemberAccount) TableName() string {
	if mg.tableName != "" {
		return mg.tableName
	}
	return defaultManagedGroupMemberAccountTableName
}

// SetTableName sets the table name.
func (mg *ManagedGroupMemberAccount) SetTableName(n string) {
	mg.tableName = n
}
