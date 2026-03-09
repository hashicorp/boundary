// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// RoleType defines the possible types for roles.
type RoleType uint32

const (
	UnknownRoleType      RoleType = 0
	UserRoleType         RoleType = 1
	GroupRoleType        RoleType = 2
	ManagedGroupRoleType RoleType = 3
)

// String returns a string representation of the role type.
func (r RoleType) String() string {
	return [...]string{
		"unknown",
		"user",
		"group",
		"managed group",
	}[r]
}

const (
	principalRoleViewDefaultTable = "iam_principal_role"
	userRoleDefaultTable          = "iam_user_role"
	groupRoleDefaultTable         = "iam_group_role"
	managedGroupRoleDefaultTable  = "iam_managed_group_role"
)

// PrincipalRole provides a common way to return roles regardless of their
// underlying type.
type PrincipalRole struct {
	*store.PrincipalRoleView
	tableName string `gorm:"-"`
}

// TableName provides an overridden gorm table name for principal roles.
func (v *PrincipalRole) TableName() string {
	if v.tableName != "" {
		return v.tableName
	}
	return principalRoleViewDefaultTable
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (v *PrincipalRole) SetTableName(n string) {
	switch n {
	case "":
		v.tableName = principalRoleViewDefaultTable
	default:
		v.tableName = n
	}
}

// UserRole is a user assigned to a role
type UserRole struct {
	*store.UserRole
	tableName string `gorm:"-"`
}

// ensure that UserRole implements the interfaces of:  Cloneable and
// db.VetForWriter
var (
	_ Cloneable       = (*UserRole)(nil)
	_ db.VetForWriter = (*UserRole)(nil)
)

// NewUserRole creates a new user role in memory. No options are supported
// currently.
func NewUserRole(ctx context.Context, roleId, userId string, _ ...Option) (*UserRole, error) {
	const op = "iam.NewUserRole"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	return &UserRole{
		UserRole: &store.UserRole{
			PrincipalId: userId,
			RoleId:      roleId,
		},
	}, nil
}

func allocUserRole() UserRole {
	return UserRole{
		UserRole: &store.UserRole{},
	}
}

// Clone creates a clone of the UserRole.
func (r *UserRole) Clone() any {
	cp := proto.Clone(r.UserRole)
	return &UserRole{
		UserRole: cp.(*store.UserRole),
	}
}

// VetForWrite implements db.VetForWrite() interface for user roles.
func (r *UserRole) VetForWrite(ctx context.Context, _ db.Reader, _ db.OpType, _ ...db.Option) error {
	const op = "iam.(UserRole).VetForWrite"
	if r.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if r.PrincipalId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name for
// user roles.
func (r *UserRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return userRoleDefaultTable
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (r *UserRole) SetTableName(n string) {
	switch n {
	case "":
		r.tableName = userRoleDefaultTable
	default:
		r.tableName = n
	}
}

// GroupRole is a group assigned to a role
type GroupRole struct {
	*store.GroupRole
	tableName string `gorm:"-"`
}

// ensure that GroupRole implements the interfaces of: Cloneable and
// db.VetForWriter
var (
	_ Cloneable       = (*GroupRole)(nil)
	_ db.VetForWriter = (*GroupRole)(nil)
)

// NewGroupRole creates a new group role in memory. No options are supported
// currently.
func NewGroupRole(ctx context.Context, roleId, groupId string, opt ...Option) (*GroupRole, error) {
	const op = "iam.NewGroupRole"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if groupId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing group id")
	}
	return &GroupRole{
		GroupRole: &store.GroupRole{
			PrincipalId: groupId,
			RoleId:      roleId,
		},
	}, nil
}

func allocGroupRole() GroupRole {
	return GroupRole{
		GroupRole: &store.GroupRole{},
	}
}

// Clone creates a clone of the GroupRole.
func (r *GroupRole) Clone() any {
	cp := proto.Clone(r.GroupRole)
	return &GroupRole{
		GroupRole: cp.(*store.GroupRole),
	}
}

// VetForWrite implements db.VetForWrite() interface for group roles.
func (r *GroupRole) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(GroupRole).VetForWrite"
	if r.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if r.PrincipalId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing group id")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name for
// group roles.
func (r *GroupRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return groupRoleDefaultTable
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (r *GroupRole) SetTableName(n string) {
	switch n {
	case "":
		r.tableName = groupRoleDefaultTable
	default:
		r.tableName = n
	}
}

// ManagedGroupRole is a managed group assigned to a role
type ManagedGroupRole struct {
	*store.ManagedGroupRole
	tableName string `gorm:"-"`
}

// ensure that GroupRole implements the interfaces of: Cloneable and
// db.VetForWriter
var (
	_ Cloneable       = (*ManagedGroupRole)(nil)
	_ db.VetForWriter = (*ManagedGroupRole)(nil)
)

// NewGroupRole creates a new group role in memory. No options are supported
// currently.
func NewManagedGroupRole(ctx context.Context, roleId, managedGroupId string, opt ...Option) (*ManagedGroupRole, error) {
	const op = "iam.NewManagedGroupRole"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if managedGroupId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing managed group id")
	}
	return &ManagedGroupRole{
		ManagedGroupRole: &store.ManagedGroupRole{
			PrincipalId: managedGroupId,
			RoleId:      roleId,
		},
	}, nil
}

// AllocManagedGroupRole returns a new ManagedGroupRole with an initialized
// store.
func AllocManagedGroupRole() ManagedGroupRole {
	return ManagedGroupRole{
		ManagedGroupRole: &store.ManagedGroupRole{},
	}
}

// Clone creates a clone of the ManagedGroupRole.
func (r *ManagedGroupRole) Clone() any {
	cp := proto.Clone(r.ManagedGroupRole)
	return &ManagedGroupRole{
		ManagedGroupRole: cp.(*store.ManagedGroupRole),
	}
}

// VetForWrite implements db.VetForWrite() interface for managed group roles.
func (r ManagedGroupRole) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(ManagedGroupRole).VetForWrite"
	if r.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if r.PrincipalId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing managed group id")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name for
// managed group roles.
func (r *ManagedGroupRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return managedGroupRoleDefaultTable
}

// SetTableName sets the table name for the resource. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (r *ManagedGroupRole) SetTableName(n string) {
	switch n {
	case "":
		r.tableName = managedGroupRoleDefaultTable
	default:
		r.tableName = n
	}
}
