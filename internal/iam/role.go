// Copyright (c) HashiCorp, Inc.
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
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

const (
	defaultRoleTableName = "iam_role"
)

// Roles are granted permissions and assignable to Users and Groups.
type Role struct {
	*store.Role
	tableName string `gorm:"-"`
}

// ensure that Role implements the interfaces of: Resource, Cloneable, and db.VetForWriter.
var (
	_ Resource        = (*Role)(nil)
	_ Cloneable       = (*Role)(nil)
	_ db.VetForWriter = (*Role)(nil)
)

// NewRole creates a new in memory role with a scope (project/org)
// allowed options include: withDescription, WithName.
func NewRole(ctx context.Context, scopeId string, opt ...Option) (*Role, error) {
	const op = "iam.NewRole"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)
	r := &Role{
		Role: &store.Role{
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return r, nil
}

func allocRole() Role {
	return Role{
		Role: &store.Role{},
	}
}

// Clone creates a clone of the Role.
func (role *Role) Clone() any {
	cp := proto.Clone(role.Role)
	return &Role{
		Role: cp.(*store.Role),
	}
}

// VetForWrite implements db.VetForWrite() interface.
func (role *Role) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(Role).VetForWrite"
	if role.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, role, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (role *Role) validScopeTypes() []scope.Type {
	return []scope.Type{scope.Global, scope.Org, scope.Project}
}

// GetScope returns the scope for the Role.
func (role *Role) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, role)
}

// GetResourceType returns the type of the Role.
func (*Role) GetResourceType() resource.Type { return resource.Role }

// Actions returns the available actions for Role.
func (*Role) Actions() map[string]action.Type {
	ret := CrudlActions()
	ret[action.AddGrants.String()] = action.AddGrants
	ret[action.RemoveGrants.String()] = action.RemoveGrants
	ret[action.SetGrants.String()] = action.SetGrants
	ret[action.AddPrincipals.String()] = action.AddPrincipals
	ret[action.RemovePrincipals.String()] = action.RemovePrincipals
	ret[action.SetPrincipals.String()] = action.SetPrincipals
	return ret
}

// TableName returns the tablename to override the default gorm table name.
func (role *Role) TableName() string {
	if role.tableName != "" {
		return role.tableName
	}
	return defaultRoleTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (role *Role) SetTableName(n string) {
	role.tableName = n
}

type deletedRole struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedRole) TableName() string {
	return "iam_role_deleted"
}
