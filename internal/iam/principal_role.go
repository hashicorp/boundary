package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

// RoleType defines the possible types for roles
type RoleType uint32

const (
	UnknownRoleType   RoleType = 0
	UserRoleType      RoleType = 1
	UserAliasRoleType RoleType = 2
	GroupRoleType     RoleType = 3
)

type PrincipalRole interface {
	Resource
	GetId() uint32
	GetRoleId() uint32
	GetPrincipalId() uint32
	GetType() uint32
	GetOwnerId() uint32
}

type principalRoleView struct {
	*store.PrincipalRoleView
}

func (v *principalRoleView) TableName() string { return "iam_principal_role_vw" }

// NewGroupMember creates a new role for the principal (User, UserAlias, Group) with a scope (project/organization), owner (user)
// options include: withFriendlyName
func NewPrincipalRole(primaryScope *Scope, role *Role, principal Resource, opt ...Option) (PrincipalRole, error) {
	if principal.ResourceType() == ResourceTypeUser {
		if u, ok := principal.(*User); ok {
			return NewUserRole(primaryScope, role, u, opt...)
		}
		return nil, errors.New("error principal is not a user ptr")
	}
	if principal.ResourceType() == ResourceTypeUserAlias {
		if a, ok := principal.(*UserAlias); ok {
			return NewUserAliasRole(primaryScope, role, a, opt...)
		}
		return nil, errors.New("error principal is not a user alias ptr")
	}
	if principal.ResourceType() == ResourceTypeGroup {
		if a, ok := principal.(*Group); ok {
			return NewGroupRole(primaryScope, role, a, opt...)
		}
		return nil, errors.New("error principal is not a user alias ptr")
	}
	return nil, errors.New("error unknown principal type")
}

type UserRole struct {
	*store.UserRole
	tableName string `gorm:"-"`
}

var _ Resource = (*UserRole)(nil)
var _ PrincipalRole = (*UserRole)(nil)
var _ db.VetForWriter = (*UserRole)(nil)

// NewUserRole creates a new user role with a scope (project/organization), owner (user)
// options include:  withFriendlyName
func NewUserRole(primaryScope *Scope, r *Role, u *User, opt ...Option) (PrincipalRole, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if primaryScope == nil {
		return nil, errors.New("error the user role primary scope is nil")
	}
	if u == nil {
		return nil, errors.New("error the user is nil")
	}
	if u.Id == 0 {
		return nil, errors.New("error the user id == 0")
	}
	if r == nil {
		return nil, errors.New("error the user role is nil")
	}
	if r.Id == 0 {
		return nil, errors.New("error the user role id == 0")
	}
	if r.OwnerId == 0 {
		return nil, errors.New("error the user role owner_id == 0")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("user roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new user role", err)
	}
	ur := &UserRole{
		UserRole: &store.UserRole{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			OwnerId:        r.OwnerId,
			PrincipalId:    u.Id,
			RoleId:         r.Id,
			Type:           uint32(UserRoleType),
		},
	}
	if withFriendlyName != "" {
		ur.FriendlyName = withFriendlyName
	}
	return ur, nil
}

// VetForWrite implements db.VetForWrite() interface
func (role *UserRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if role.PublicId == "" {
		return errors.New("error public id is empty string for user role write")
	}
	if role.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for user role write")
	}
	if role.OwnerId == 0 {
		return errors.New("error owner id == 0 for user role write")
	}
	if role.Type != uint32(UserRoleType) {
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
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization or project for user role")
	}
	return nil
}

// GetOwner returns the owner (User) of the user role
func (role *UserRole) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	return LookupOwner(ctx, r, role)
}

// GetPrimaryScope returns the PrimaryScope for the user role
func (role *UserRole) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, role)
}

// ResourceType returns the type of the user role
func (*UserRole) ResourceType() ResourceType { return ResourceTypePrincipalRole }

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

type UserAliasRole struct {
	*store.UserAliasRole
	tableName string `gorm:"-"`
}

var _ Resource = (*UserAliasRole)(nil)
var _ PrincipalRole = (*UserAliasRole)(nil)
var _ db.VetForWriter = (*UserAliasRole)(nil)

// NewUserRole creates a new user alias role with a scope (project/organization), owner (user)
// options include:  withFriendlyName
func NewUserAliasRole(primaryScope *Scope, r *Role, u *UserAlias, opt ...Option) (PrincipalRole, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if primaryScope == nil {
		return nil, errors.New("error the user alias role primary scope is nil")
	}
	if u == nil {
		return nil, errors.New("error the user alias is nil")
	}
	if u.Id == 0 {
		return nil, errors.New("error the user alias id == 0")
	}
	if r == nil {
		return nil, errors.New("error the user alias role is nil")
	}
	if r.Id == 0 {
		return nil, errors.New("error the user alias role id == 0")
	}
	if r.OwnerId == 0 {
		return nil, errors.New("error the user alias role owner_id == 0")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("user alias roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new user alias role", err)
	}
	ur := &UserAliasRole{
		UserAliasRole: &store.UserAliasRole{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			OwnerId:        r.OwnerId,
			PrincipalId:    u.Id,
			RoleId:         r.Id,
			Type:           uint32(UserAliasRoleType),
		},
	}
	if withFriendlyName != "" {
		ur.FriendlyName = withFriendlyName
	}
	return ur, nil
}

// VetForWrite implements db.VetForWrite() interface
func (role *UserAliasRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if role.PublicId == "" {
		return errors.New("error public id is empty string for user alias role write")
	}
	if role.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for user alias role write")
	}
	if role.OwnerId == 0 {
		return errors.New("error owner id == 0 for user alias role write")
	}
	if role.Type != uint32(UserAliasRoleType) {
		return errors.New("error role type is not user alias role")
	}
	// make sure the scope is valid for user roles
	if err := role.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (role *UserAliasRole) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, role)
	if err != nil {
		return err
	}
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization or project for user alias role")
	}
	return nil
}

// GetOwner returns the owner (User) of the user alias role
func (role *UserAliasRole) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	return LookupOwner(ctx, r, role)
}

// GetPrimaryScope returns the PrimaryScope for the user alias role
func (role *UserAliasRole) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, role)
}

// ResourceType returns the type of the user alias role
func (*UserAliasRole) ResourceType() ResourceType { return ResourceTypePrincipalRole }

// Actions returns the  available actions for user alias role
func (*UserAliasRole) Actions() map[string]Action {
	return StdActions()
}

// TableName returns the tablename to override the default gorm table name
func (r *UserAliasRole) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "iam_role_user_alias"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (r *UserAliasRole) SetTableName(n string) {
	if r.tableName != "" {
		r.tableName = n
	}
}

type GroupRole struct {
	*store.GroupRole
	tableName string `gorm:"-"`
}

var _ Resource = (*GroupRole)(nil)
var _ PrincipalRole = (*GroupRole)(nil)
var _ db.VetForWriter = (*GroupRole)(nil)

// GroupRole creates a new group role with a scope (project/organization), owner (user)
// options include:  withFriendlyName
func NewGroupRole(primaryScope *Scope, r *Role, g *Group, opt ...Option) (PrincipalRole, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if primaryScope == nil {
		return nil, errors.New("error the group role primary scope is nil")
	}
	if g == nil {
		return nil, errors.New("error the group is nil")
	}
	if g.Id == 0 {
		return nil, errors.New("error the group id == 0")
	}
	if r == nil {
		return nil, errors.New("error the group role is nil")
	}
	if r.Id == 0 {
		return nil, errors.New("error the group role id == 0")
	}
	if r.OwnerId == 0 {
		return nil, errors.New("error the group role owner_id == 0")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("group roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new group role", err)
	}
	gr := &GroupRole{
		GroupRole: &store.GroupRole{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			OwnerId:        r.OwnerId,
			PrincipalId:    g.Id,
			RoleId:         r.Id,
			Type:           uint32(GroupRoleType),
		},
	}
	if withFriendlyName != "" {
		gr.FriendlyName = withFriendlyName
	}
	return gr, nil
}

// VetForWrite implements db.VetForWrite() interface
func (role *GroupRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if role.PublicId == "" {
		return errors.New("error public id is empty string for group role write")
	}
	if role.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for group role write")
	}
	if role.OwnerId == 0 {
		return errors.New("error owner id == 0 for group ole write")
	}
	if role.Type != uint32(GroupRoleType) {
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
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization or project for group role")
	}
	return nil
}

// GetOwner returns the owner (User) of the group role
func (role *GroupRole) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	return LookupOwner(ctx, r, role)
}

// GetPrimaryScope returns the PrimaryScope for the group role
func (role *GroupRole) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, role)
}

// ResourceType returns the type of the group role
func (*GroupRole) ResourceType() ResourceType { return ResourceTypePrincipalRole }

// Actions returns the  available actions for user alias role
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
