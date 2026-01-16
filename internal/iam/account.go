// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	authStore "github.com/hashicorp/boundary/internal/auth/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const (
	defaultAccountTableName = "auth_account"
)

// authAccount is from the auth subsystem and iam is only allowed to: lookup and
// update auth accounts.  That's why there is no "new" factory for Accounts.
type authAccount struct {
	*authStore.Account
	tableName string `gorm:"-"`
}

var (
	_ Cloneable               = (*authAccount)(nil)
	_ db.VetForWriter         = (*authAccount)(nil)
	_ oplog.ReplayableMessage = (*authAccount)(nil)
)

func allocAccount() authAccount {
	return authAccount{
		Account: &authStore.Account{},
	}
}

// Clone creates a clone of the auth account.
func (a *authAccount) Clone() any {
	cp := proto.Clone(a.Account)
	return &authAccount{
		Account: cp.(*authStore.Account),
	}
}

// VetForWrite implements db.VetForWrite() interface.
func (a *authAccount) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(authAccount).VetForWrite"
	if a.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, a, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (a *authAccount) getResourceType() resource.Type {
	return resource.Account
}

// GetScope returns the scope for the auth account.
func (a *authAccount) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, a)
}

// TableName returns the tablename to override the default gorm table name.
func (a *authAccount) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return defaultAccountTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (a *authAccount) SetTableName(n string) {
	a.tableName = n
}
