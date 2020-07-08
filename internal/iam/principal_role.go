package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// RoleType defines the possible types for roles.
type RoleType uint32

const (
	UnknownRoleType RoleType = 0
	UserRoleType    RoleType = 1
	GroupRoleType   RoleType = 2
)

// String returns a string representation of the role type.
func (r RoleType) String() string {
	return [...]string{
		"unknown",
		"user",
		"group",
	}[r]
}

const principalRoleViewDefaultTable = "iam_principal_role"

// PrincipalRole declares a common interface for all roles assigned to resources (Users and Groups).
type PrincipalRole interface {
	GetRoleId() string
	GetPrincipalId() string
	GetType() string
	GetScopeId() string
	Clone() interface{}
}

// principalRoleView provides a common way to return roles regardless of their
// underlying type.
type principalRoleView struct {
	*store.PrincipalRoleView
	tableName string `gorm:"-"`
}

// TableName provides an overridden gorm table name for principal roles.
func (v *principalRoleView) TableName() string {
	if v.tableName != "" {
		return v.tableName
	}
	return principalRoleViewDefaultTable
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (v *principalRoleView) SetTableName(n string) {
	switch n {
	case "":
		v.tableName = principalRoleViewDefaultTable
	default:
		v.tableName = n
	}
}

func (v principalRoleView) Clone() interface{} {
	cp := proto.Clone(v.PrincipalRoleView)
	return &principalRoleView{
		PrincipalRoleView: cp.(*store.PrincipalRoleView),
	}
}

// UserRole is a role assigned to a user
type UserRole struct {
	*store.UserRole
	tableName string `gorm:"-"`
}

// ensure that UserRole implements the interfaces of:  Clonable, AssignedRole
// and db.VetForWriter
var _ Clonable = (*UserRole)(nil)
var _ PrincipalRole = (*UserRole)(nil)
var _ db.VetForWriter = (*UserRole)(nil)

// NewUserRole creates a new user role in memory.  Users can be assigned roles
// which are within its organization, or the role is within a project within its
// organization. This relationship will not be enforced until the user role is
// written to the database.  No options are supported currently.
func NewUserRole(scopeId, roleId, userId string, opt ...Option) (PrincipalRole, error) {
	if roleId == "" {
		return nil, fmt.Errorf("new user role: missing role id %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return nil, fmt.Errorf("new user role: missing user id %w", db.ErrInvalidParameter)
	}
	return &UserRole{
		UserRole: &store.UserRole{
			PrincipalId: userId,
			RoleId:      roleId,
			ScopeId:     scopeId,
		},
	}, nil
}

// GetType returns the user role type.
func (r *UserRole) GetType() string {
	return UserRoleType.String()
}

func allocUserRole() UserRole {
	return UserRole{
		UserRole: &store.UserRole{},
	}
}

// Clone creates a clone of the UserRole.
func (r *UserRole) Clone() interface{} {
	cp := proto.Clone(r.UserRole)
	return &UserRole{
		UserRole: cp.(*store.UserRole),
	}
}

// VetForWrite implements db.VetForWrite() interface for user roles.  The
// constraint between user and role scopes will be enforced by the database via
// constraints and triggers.
func (role *UserRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if role.RoleId == "" {
		return fmt.Errorf("new user role: missing role id %w", db.ErrInvalidParameter)
	}
	if role.PrincipalId == "" {
		return fmt.Errorf("new user role: missing user id %w", db.ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name for
// user roles.
func (r *UserRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "iam_user_role"
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
var _ PrincipalRole = (*GroupRole)(nil)
var _ db.VetForWriter = (*GroupRole)(nil)

// NewGroupRole creates a new group role in memory.  Groups can only be
// assigned roles within its scope (org or project). This relationship will not
// be enforced until the group role is written to the database. No options are
// supported currently.
func NewGroupRole(scopeId, roleId, groupId string, opt ...Option) (PrincipalRole, error) {
	if roleId == "" {
		return nil, fmt.Errorf("new group role: missing role id %w", db.ErrInvalidParameter)
	}
	if groupId == "" {
		return nil, fmt.Errorf("new group role: missing group id %w", db.ErrInvalidParameter)
	}
	return &GroupRole{
		GroupRole: &store.GroupRole{
			PrincipalId: groupId,
			RoleId:      roleId,
			ScopeId:     scopeId,
		},
	}, nil
}

// GetType returns the group role type.
func (r *GroupRole) GetType() string {
	return GroupRoleType.String()
}

func allocGroupRole() GroupRole {
	return GroupRole{
		GroupRole: &store.GroupRole{},
	}
}

// Clone creates a clone of the GroupRole.
func (r *GroupRole) Clone() interface{} {
	cp := proto.Clone(r.GroupRole)
	return &GroupRole{
		GroupRole: cp.(*store.GroupRole),
	}
}

// VetForWrite implements db.VetForWrite() interface for group roles. The
// constraint between groups and role scopes will be enforced by the database via
// constraints and triggers.
func (role *GroupRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if role.RoleId == "" {
		return fmt.Errorf("new group role: missing role id %w", db.ErrInvalidParameter)
	}
	if role.PrincipalId == "" {
		return fmt.Errorf("new group role: missing user id %w", db.ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name for
// group roles.
func (r *GroupRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "iam_group_role"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
// for group roles.
func (r *GroupRole) SetTableName(n string) {
	if r.tableName != "" {
		r.tableName = n
	}
}
