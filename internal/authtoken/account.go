// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	authStore "github.com/hashicorp/boundary/internal/auth/store"
	"google.golang.org/protobuf/proto"
)

const (
	defaultAuthAccountTableName = "auth_account"
)

// AuthAccount is from the auth subsystem and iam is only allowed to: lookup and
// update auth accounts.  That's why there is no "new" factory for AuthAccounts.
type authAccount struct {
	*authStore.Account
	tableName string `gorm:"-"`
}

func allocAuthAccount() *authAccount {
	return &authAccount{
		Account: &authStore.Account{},
	}
}

// Clone creates a clone of the auth account.
func (a *authAccount) clone() *authAccount {
	cp := proto.Clone(a.Account)
	return &authAccount{
		Account: cp.(*authStore.Account),
	}
}

// TableName returns the tablename to override the default gorm table name.
func (a *authAccount) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return defaultAuthAccountTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (a *authAccount) SetTableName(n string) {
	a.tableName = n
}
