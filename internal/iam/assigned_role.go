package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
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
	Resource
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
func NewAssignedRole(primaryScope *Scope, role *Role, principal Resource, opt ...Option) (AssignedRole, error) {
	if primaryScope == nil {
		return nil, errors.New("error scope is nil for assigning role")
	}
	if primaryScope.PublicId == "" {
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
			return newUserRole(primaryScope, role, u, opt...)
		}
		return nil, errors.New("error principal is not a user ptr for assigning role")
	}
	if principal.ResourceType() == ResourceTypeGroup {
		if a, ok := principal.(*Group); ok {
			return newGroupRole(primaryScope, role, a, opt...)
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

// ensure that UserRole implements the interfaces of: Resource, ClonableResource, AssignedRole and db.VetForWriter
var _ Resource = (*UserRole)(nil)
var _ ClonableResource = (*UserRole)(nil)
var _ AssignedRole = (*UserRole)(nil)
var _ db.VetForWriter = (*UserRole)(nil)

// newUserRole creates a new user role with a scope (project/organization)
// options include:  WithName
func newUserRole(primaryScope *Scope, r *Role, u *User, opt ...Option) (AssignedRole, error) {
	opts := GetOpts(opt...)
	withName := opts.withName
	if primaryScope == nil {
		return nil, errors.New("error the user role primary scope is nil")
	}
	if u == nil {
		return nil, errors.New("error the user is nil")
	}
	if u.PublicId == "" {
		return nil, errors.New("error the user id is unset")
	}
	if r == nil {
		return nil, errors.New("error the user role is nil")
	}
	if r.PublicId == "" {
		return nil, errors.New("error the user role id is unset")
	}
	if primaryScope.Type != OrganizationScope.String() &&
		primaryScope.Type != ProjectScope.String() {
		return nil, errors.New("user roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new user role", err)
	}
	ur := &UserRole{
		UserRole: &store.UserRole{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetPublicId(),
			PrincipalId:    u.PublicId,
			RoleId:         r.PublicId,
			Type:           UserRoleType.String(),
		},
	}
	if withName != "" {
		ur.Name = withName
	}
	return ur, nil
}

// Clone creates a clone of the UserRole
func (r *UserRole) Clone() Resource {
	cp := proto.Clone(r.UserRole)
	return &UserRole{
		UserRole: cp.(*store.UserRole),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (role *UserRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if role.PublicId == "" {
		return errors.New("error public id is empty string for user role write")
	}
	if role.PrimaryScopeId == "" {
		return errors.New("error primary scope id not set for user role write")
	}
	if role.Type != UserRoleType.String() {
		return errors.New("error role type is not user")
	}
	// make sure the scope is valid for user roles
	if err := role.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (role *UserRole) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, role)
	if err != nil {
		return err
	}
	if ps.Type != OrganizationScope.String() && ps.Type != ProjectScope.String() {
		return errors.New("error primary scope is not an organization or project for user role")
	}
	return nil
}

// GetPrimaryScope returns the PrimaryScope for the user role
func (role *UserRole) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, role)
}

// ResourceType returns the type of the user role
func (*UserRole) ResourceType() ResourceType { return ResourceTypeAssignedUserRole }

// Actions returns the  available actions for user role
func (*UserRole) Actions() map[string]Action {
	return StdActions()
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

// ensure that GroupRole implements the interfaces of: Resource, ClonableResource, AssignedRole and db.VetForWriter
var _ Resource = (*GroupRole)(nil)
var _ ClonableResource = (*GroupRole)(nil)
var _ AssignedRole = (*GroupRole)(nil)
var _ db.VetForWriter = (*GroupRole)(nil)

// newGroupRole creates a new group role with a scope (project/organization)
// options include:  WithName
func newGroupRole(primaryScope *Scope, r *Role, g *Group, opt ...Option) (AssignedRole, error) {
	opts := GetOpts(opt...)
	withName := opts.withName
	if primaryScope == nil {
		return nil, errors.New("error the group role primary scope is nil")
	}
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
	if primaryScope.Type != OrganizationScope.String() &&
		primaryScope.Type != ProjectScope.String() {
		return nil, errors.New("group roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new group role", err)
	}
	gr := &GroupRole{
		GroupRole: &store.GroupRole{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetPublicId(),
			PrincipalId:    g.PublicId,
			RoleId:         r.PublicId,
			Type:           GroupRoleType.String(),
		},
	}
	if withName != "" {
		gr.Name = withName
	}
	return gr, nil
}

// Clone creates a clone of the GroupRole
func (r *GroupRole) Clone() Resource {
	cp := proto.Clone(r.GroupRole)
	return &GroupRole{
		GroupRole: cp.(*store.GroupRole),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (role *GroupRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if role.PublicId == "" {
		return errors.New("error public id is empty string for group role write")
	}
	if role.PrimaryScopeId == "" {
		return errors.New("error primary scope id not set for group role write")
	}
	if role.Type != GroupRoleType.String() {
		return errors.New("error role type is not group")
	}
	// make sure the scope is valid for user roles
	if err := role.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (role *GroupRole) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, role)
	if err != nil {
		return err
	}
	if ps.Type != OrganizationScope.String() && ps.Type != ProjectScope.String() {
		return errors.New("error primary scope is not an organization or project for group role")
	}
	return nil
}

// GetPrimaryScope returns the PrimaryScope for the group role
func (role *GroupRole) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, role)
}

// ResourceType returns the type of the group role
func (*GroupRole) ResourceType() ResourceType { return ResourceTypeAssignedGroupRole }

// Actions returns the  available actions for group role
func (*GroupRole) Actions() map[string]Action {
	return StdActions()
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
