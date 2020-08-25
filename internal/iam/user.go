package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

const (
	defaultUserTableName = "iam_user"
)

// User defines boundary users which are scoped to an Org
type User struct {
	*store.User
	tableName string `gorm:"-"`
}

// ensure that User implements the interfaces of: Resource, Cloneable and db.VetForWriter
var _ Resource = (*User)(nil)
var _ Cloneable = (*User)(nil)
var _ db.VetForWriter = (*User)(nil)

// NewUser creates a new in memory user and allows options:
// WithName - to specify the user's friendly name and WithDescription - to
// specify a user description
func NewUser(scopeId string, opt ...Option) (*User, error) {
	opts := getOpts(opt...)
	if scopeId == "" {
		return nil, fmt.Errorf("new user: missing scope id %w", db.ErrInvalidParameter)
	}
	u := &User{
		User: &store.User{
			Name:        opts.withName,
			Description: opts.withDescription,
			ScopeId:     scopeId,
		},
	}
	return u, nil
}

func allocUser() User {
	return User{
		User: &store.User{},
	}
}

// Clone creates a clone of the User
func (u *User) Clone() interface{} {
	cp := proto.Clone(u.User)
	return &User{
		User: cp.(*store.User),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the user
// before it's written.
func (u *User) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if u.PublicId == "" {
		return fmt.Errorf("user vet for write: missing public id: %w", db.ErrInvalidParameter)
	}
	if err := validateScopeForWrite(ctx, r, u, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (u *User) validScopeTypes() []scope.Type {
	return []scope.Type{scope.Global, scope.Org}
}

// GetScope returns the scope for the User
func (u *User) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, u)
}

// ResourceType returns the type of the User
func (*User) ResourceType() resource.Type { return resource.User }

// Actions returns the  available actions for Users
func (*User) Actions() map[string]action.Type {
	return CrudActions()
}

// TableName returns the tablename to override the default gorm table name
func (u *User) TableName() string {
	if u.tableName != "" {
		return u.tableName
	}
	return defaultUserTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (u *User) SetTableName(n string) {
	u.tableName = n
}
