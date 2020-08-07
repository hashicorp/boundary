package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

const (
	defaultAccountTableName = "auth_account"
)

// Account is from the auth subsystem and iam is only allowed to: lookup and
// update auth accounts.  That's why there is no "new" factory for Accounts.
type Account struct {
	*store.Account
	tableName string `gorm:"-"`
}

var _ Cloneable = (*Account)(nil)
var _ db.VetForWriter = (*Account)(nil)
var _ oplog.ReplayableMessage = (*Account)(nil)

func allocAccount() Account {
	return Account{
		Account: &store.Account{},
	}
}

// Clone creates a clone of the auth account.
func (a *Account) Clone() interface{} {
	cp := proto.Clone(a.Account)
	return &Account{
		Account: cp.(*store.Account),
	}
}

// VetForWrite implements db.VetForWrite() interface.
func (a *Account) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if a.PublicId == "" {
		return fmt.Errorf("error public id is empty string for auth account write: %w", db.ErrInvalidParameter)
	}
	if err := validateScopeForWrite(ctx, r, a, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (a *Account) validScopeTypes() []scope.Type {
	return []scope.Type{scope.Org}
}

// GetScope returns the scope for the auth account.
func (a *Account) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, a)
}

// TableName returns the tablename to override the default gorm table name.
func (a *Account) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return defaultAccountTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (a *Account) SetTableName(n string) {
	a.tableName = n
}
