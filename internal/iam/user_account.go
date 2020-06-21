package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

type UserAccount struct {
	*store.UserAccount
	tableName string `gorm:-`
}

var _ Clonable = (*UserAccount)(nil)
var _ db.VetForWriter = (*UserAccount)(nil)

// NewUserAccount creates a new in memory user account within a scope
// (organization) and associated with an authMethod and an authMethod account.
func NewUserAccount(scopeId, userId, authMethodId, authAccountId string) (*UserAccount, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new user account: missing scope id %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return nil, fmt.Errorf("new user account: missing user id %w", db.ErrInvalidParameter)
	}
	if authMethodId == "" {
		return nil, fmt.Errorf("new user account: missing auth method id %w", db.ErrInvalidParameter)
	}
	if authAccountId == "" {
		return nil, fmt.Errorf("new user account: missing auth account id %w", db.ErrInvalidParameter)
	}
	return &UserAccount{
		UserAccount: &store.UserAccount{
			ScopeId:       scopeId,
			UserId:        userId,
			AuthMethodId:  authMethodId,
			AuthAccountId: authAccountId,
		},
	}, nil
}

func allocUserAccount() UserAccount {
	return UserAccount{
		UserAccount: &store.UserAccount{},
	}
}

// Clone creates a clone of the user account.
func (a *UserAccount) Clone() interface{} {
	cp := proto.Clone(a.UserAccount)
	return &UserAccount{
		UserAccount: cp.(*store.UserAccount),
	}
}

// VetForWrite implements db.VetForWrite() interface.
func (a *UserAccount) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if a.PrivateId == "" {
		return fmt.Errorf("error private id is empty string for user account write: %w", db.ErrInvalidParameter)
	}
	if err := validateScopeForWrite(ctx, r, a, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (a *UserAccount) validScopeTypes() []ScopeType {
	return []ScopeType{OrganizationScope}
}

// Getscope returns the scope for the Role.
func (a *UserAccount) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, a)
}

// TableName returns the tablename to override the default gorm table name.
func (a *UserAccount) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return "iam_user_account"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface.
func (a *UserAccount) SetTableName(n string) {
	if n != "" {
		a.tableName = n
	}
}
