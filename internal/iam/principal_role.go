package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
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

const (
	principalRoleViewDefaultTable = "iam_principal_role"
	userRoleDefaultTable          = "iam_user_role"
	groupRoleDefaultTable         = "iam_group_role"
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
var _ Cloneable = (*UserRole)(nil)
var _ db.VetForWriter = (*UserRole)(nil)

// NewUserRole creates a new user role in memory. No options are supported
// currently.
func NewUserRole(roleId, userId string, opt ...Option) (*UserRole, error) {
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
		},
	}, nil
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

// VetForWrite implements db.VetForWrite() interface for user roles.
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

//  GroupRole is a group assigned to a role
type GroupRole struct {
	*store.GroupRole
	tableName string `gorm:"-"`
}

// ensure that GroupRole implements the interfaces of: Cloneable and
// db.VetForWriter
var _ Cloneable = (*GroupRole)(nil)
var _ db.VetForWriter = (*GroupRole)(nil)

// NewGroupRole creates a new group role in memory. No options are supported
// currently.
func NewGroupRole(roleId, groupId string, opt ...Option) (*GroupRole, error) {
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
		},
	}, nil
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

// VetForWrite implements db.VetForWrite() interface for group roles.
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
