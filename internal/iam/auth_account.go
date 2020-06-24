package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// AuthAccount is from the auth subsystem and iam is only allowed to: lookup and
// update auth accounts.  That's why there is no "new" factory for AuthAccounts.
type AuthAccount struct {
	*store.AuthAccount
	tableName string `gorm:"-"`
}

var _ Clonable = (*AuthAccount)(nil)
var _ db.VetForWriter = (*AuthAccount)(nil)
var _ oplog.ReplayableMessage = (*AuthAccount)(nil)

func allocAuthAccount() AuthAccount {
	return AuthAccount{
		AuthAccount: &store.AuthAccount{},
	}
}

// Clone creates a clone of the user account.
func (a *AuthAccount) Clone() interface{} {
	cp := proto.Clone(a.AuthAccount)
	return &AuthAccount{
		AuthAccount: cp.(*store.AuthAccount),
	}
}

// VetForWrite implements db.VetForWrite() interface.
func (a *AuthAccount) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if a.PublicId == "" {
		return fmt.Errorf("error public id is empty string for auth account write: %w", db.ErrInvalidParameter)
	}
	if err := validateScopeForWrite(ctx, r, a, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (a *AuthAccount) validScopeTypes() []ScopeType {
	return []ScopeType{OrganizationScope}
}

// Getscope returns the scope for the Role.
func (a *AuthAccount) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, a)
}

// TableName returns the tablename to override the default gorm table name.
func (a *AuthAccount) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return "auth_account"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface.
func (a *AuthAccount) SetTableName(n string) {
	if n != "" {
		a.tableName = n
	}
}
