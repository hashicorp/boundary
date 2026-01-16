// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const (
	defaultUserTableName            = "iam_user"
	defaultUserAccountInfoTableName = "iam_user_acct_info"
)

// User defines boundary users which are scoped to an Org
type User struct {
	*store.User
	tableName string `gorm:"-"`
}

// ensure that User implements the interfaces of: Resource, Cloneable and db.VetForWriter
var (
	_ Resource        = (*User)(nil)
	_ Cloneable       = (*User)(nil)
	_ db.VetForWriter = (*User)(nil)
)

// NewUser creates a new in memory user and allows options:
// WithName - to specify the user's friendly name and WithDescription - to
// specify a user description
func NewUser(ctx context.Context, scopeId string, opt ...Option) (*User, error) {
	const op = "iam.NewUser"
	opts := getOpts(opt...)
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
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

// AllocUser will allocate an empty user
func AllocUser() User {
	return User{
		User: &store.User{},
	}
}

// Clone creates a clone of the User
func (u *User) Clone() any {
	cp := proto.Clone(u.User)
	return &User{
		User: cp.(*store.User),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the user
// before it's written.
func (u *User) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(User).VetForWrite"
	if u.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, u, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (u *User) getResourceType() resource.Type {
	return resource.User
}

// GetScope returns the scope for the User
func (u *User) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, u)
}

// GetResourceType returns the type of the User
func (*User) GetResourceType() resource.Type { return resource.User }

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

// userAccountInfo provides a way to represent a user along with the user's
// account info from the scope's primary auth method
type userAccountInfo struct {
	*store.User
	tableName string `gorm:"-"`
}

// allocUserAccountInfo will allocate an empty userAccountInfo
func allocUserAccountInfo() *userAccountInfo {
	return &userAccountInfo{
		User: &store.User{},
	}
}

func (u *userAccountInfo) shallowConversion() *User {
	return &User{
		User: u.User,
	}
}

// TableName provides an overridden gorm table name..
func (u *userAccountInfo) TableName() string {
	if u.tableName != "" {
		return u.tableName
	}
	return defaultUserAccountInfoTableName
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (u *userAccountInfo) SetTableName(n string) {
	switch n {
	case "":
		u.tableName = defaultUserAccountInfoTableName
	default:
		u.tableName = n
	}
}

type deletedUser struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (u *deletedUser) TableName() string {
	return "iam_user_deleted"
}
