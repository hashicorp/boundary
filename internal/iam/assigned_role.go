package iam

import (
	"context"
	"errors"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// RoleType defines the possible types for roles
type RoleType uint32

const (
	UnknownRoleType RoleType = 0
	UserRoleType    RoleType = 1
	GroupRoleType   RoleType = 2
)

func (r RoleType) String() string {
	return [...]string{
		"unknown",
		"user",
		"group",
	}[r]
}

// AssignedRole declares a common interface for all roles assigned to resources (Users and Groups for now)
type AssignedRole interface {
	GetRoleId() string
	GetPrincipalId() string
	GetType() string
}

// assignedRoleView provides a common way to return roles regardless of their underlying type
type assignedRoleView struct {
	*store.AssignedRoleView
}

// TableName provides an overridden gorm table name for assigned roles
func (v *assignedRoleView) TableName() string { return "iam_assigned_role_vw" }

// NewAssignedRole creates a new role for the principal (User,Group) with a scope (project/organization)
// This is the preferred way to create roles vs calling a specific role type constructor func
// options include: WithName
func NewAssignedRole(scope *Scope, role *Role, principal Resource, opt ...Option) (AssignedRole, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for assigning role")
	}
	if scope.PublicId == "" {
		return nil, errors.New("error scope id is missing for assigning role")
	}
	if role == nil {
		return nil, errors.New("error role is nil for assigning role")
	}
	if principal == nil {
		return nil, errors.New("principal is nil for assigning role")
	}
	if principal.ResourceType() == ResourceTypeUser {
		if u, ok := principal.(*User); ok {
			return newUserRole(role, u, opt...)
		}
		return nil, errors.New("error principal is not a user ptr for assigning role")
	}
	if principal.ResourceType() == ResourceTypeGroup {
		if a, ok := principal.(*Group); ok {
			return newGroupRole(role, a, opt...)
		}
		return nil, errors.New("error principal is not a group ptr for assigning role")
	}
	return nil, errors.New("error unknown principal type for assigning role")
}

// UserRole is a role assigned to a user
type UserRole struct {
	*store.UserRole
	tableName string `gorm:"-"`
}

// ensure that UserRole implements the interfaces of:  Clonable, AssignedRole and db.VetForWriter
var _ Clonable = (*UserRole)(nil)
var _ AssignedRole = (*UserRole)(nil)
var _ db.VetForWriter = (*UserRole)(nil)

// newUserRole creates a new user role. options include:  WithName
func newUserRole(r *Role, u *User, opt ...Option) (AssignedRole, error) {
	if u.PublicId == "" {
		return nil, errors.New("error the user id is unset")
	}
	if r == nil {
		return nil, errors.New("error the user role is nil")
	}
	if r.PublicId == "" {
		return nil, errors.New("error the user role id is unset")
	}
	ur := &UserRole{
		UserRole: &store.UserRole{
			PrincipalId: u.PublicId,
			RoleId:      r.PublicId,
			Type:        UserRoleType.String(),
		},
	}
	return ur, nil
}

// Clone creates a clone of the UserRole
func (r *UserRole) Clone() interface{} {
	cp := proto.Clone(r.UserRole)
	return &UserRole{
		UserRole: cp.(*store.UserRole),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (role *UserRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if role.Type != UserRoleType.String() {
		return errors.New("error role type is not user")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (r *UserRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "iam_role_user"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (r *UserRole) SetTableName(n string) {
	if r.tableName != "" {
		r.tableName = n
	}
}

//  GroupRole is a role assigned to a group
type GroupRole struct {
	*store.GroupRole
	tableName string `gorm:"-"`
}

// ensure that GroupRole implements the interfaces of: Clonable, AssignedRole and db.VetForWriter
var _ Clonable = (*GroupRole)(nil)
var _ AssignedRole = (*GroupRole)(nil)
var _ db.VetForWriter = (*GroupRole)(nil)

// newGroupRole creates a new group role.
// options include:  WithName
func newGroupRole(r *Role, g *Group, opt ...Option) (AssignedRole, error) {
	if g == nil {
		return nil, errors.New("error the group is nil")
	}
	if g.PublicId == "" {
		return nil, errors.New("error the group id is unset")
	}
	if r == nil {
		return nil, errors.New("error the group role is nil")
	}
	if r.PublicId == "" {
		return nil, errors.New("error the group role id is unset")
	}
	gr := &GroupRole{
		GroupRole: &store.GroupRole{
			PrincipalId: g.PublicId,
			RoleId:      r.PublicId,
			Type:        GroupRoleType.String(),
		},
	}
	return gr, nil
}

// Clone creates a clone of the GroupRole
func (r *GroupRole) Clone() interface{} {
	cp := proto.Clone(r.GroupRole)
	return &GroupRole{
		GroupRole: cp.(*store.GroupRole),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (role *GroupRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if role.Type != GroupRoleType.String() {
		return errors.New("error role type is not group")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (r *GroupRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "iam_role_group"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (r *GroupRole) SetTableName(n string) {
	if r.tableName != "" {
		r.tableName = n
	}
}
