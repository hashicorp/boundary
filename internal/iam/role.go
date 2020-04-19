package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

type Role struct {
	*store.Role
	tableName string `gorm:"-"`
}

var _ Resource = (*Role)(nil)

var _ db.VetForWriter = (*Role)(nil)

// NewRole creates a new role with a scope (project/organization), owner (user)
// options include: withDescripion, withFriendlyName
func NewRole(primaryScope *Scope, owner *User, opt ...Option) (*Role, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	withDescription := opts[optionWithDescription].(string)
	if primaryScope == nil {
		return nil, errors.New("error the role primary scope is nil")
	}
	if owner == nil {
		return nil, errors.New("error the role owner is nil")
	}
	if owner.Id == 0 {
		return nil, errors.New("error the role owner id == 0")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new role", err)
	}
	r := &Role{
		Role: &store.Role{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			OwnerId:        owner.Id,
		},
	}
	if withFriendlyName != "" {
		r.FriendlyName = withFriendlyName
	}
	if optionWithDescription != "" {
		r.Description = withDescription
	}
	return r, nil
}

// VetForWrite implements db.VetForWrite() interface
func (role *Role) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if role.PublicId == "" {
		return errors.New("error public id is empty string for role write")
	}
	if role.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for role write")
	}
	if role.OwnerId == 0 {
		return errors.New("error owner id == 0 for role write")
	}
	// make sure the scope is valid for users
	if err := role.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (role *Role) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, role)
	if err != nil {
		return err
	}
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization or project for role")
	}
	return nil
}

// GetOwner returns the owner (User) of the Role
func (role *Role) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	return LookupOwner(ctx, r, role)
}

// GetPrimaryScope returns the PrimaryScope for the Role
func (role *Role) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, role)
}

// ResourceType returns the type of the Role
func (*Role) ResourceType() ResourceType { return ResourceTypeRole }

// Actions returns the  available actions for Role
func (*Role) Actions() map[string]Action {
	return StdActions()
}

// TableName returns the tablename to override the default gorm table name
func (r *Role) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "iam_role"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (r *Role) SetTableName(n string) {
	if n != "" {
		r.tableName = n
	}
}
