package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

// AuthType defines the possible types for AuthMethod
type AuthType uint32

const (
	AuthUnknown  AuthType = 0
	AuthUserPass AuthType = 1
	AuthOIDC     AuthType = 2
)

// AuthMethod are the authentication methods available in different Organization and/or
// Project Scopes within WatchTower.  UserAliases must have an AuthMethod, since that's
// how they authenticate and it's really the purpose of UserAlaises (to tie users to
// different authmethods via aliases)
type AuthMethod struct {
	*store.AuthMethod
	tableName string `gorm:"-"`
}

// check that required interfaces are implemented
var _ Resource = (*AuthMethod)(nil)
var _ db.VetForWriter = (*AuthMethod)(nil)

// NewAuthMethod creates a new AuthMethod for a Scope (org or project)
// and authentication type.
func NewAuthMethod(primaryScope *Scope, authType AuthType, opt ...Option) (*AuthMethod, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if authType == AuthUnknown {
		return nil, errors.New("error unknown auth type")
	}
	if primaryScope == nil {
		return nil, errors.New("error user pass primary scope is nil")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("user pass can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new pass alias", err)
	}
	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			Type:           uint32(authType),
		},
	}
	if withFriendlyName != "" {
		a.FriendlyName = withFriendlyName
	}
	return a, nil
}

// VetForWrite implements db.VetForWrite() interface
func (p *AuthMethod) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if p.PublicId == "" {
		return errors.New("error public id is empty string for user write")
	}
	if p.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for user write")
	}
	// make sure the scope is valid for auth methods
	if err := p.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

// primaryScopeIsValid makes sure the primary scope is either an Organization or Project
func (p *AuthMethod) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, p)
	if err != nil {
		return err
	}
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization")
	}
	return nil
}

// GetPrimaryScope returns the PrimaryScope for the AuthMethod
func (p *AuthMethod) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, p)
}

// ResourceType returns the type of the AuthMethod
func (*AuthMethod) ResourceType() ResourceType { return ResourceTypeUserAlias }

// Actions returns the  available actions for AuthMethod
func (*AuthMethod) Actions() map[string]Action {
	actions := StdActions()
	return actions
}

// TableName returns the tablename to override the default gorm table name
func (p *AuthMethod) TableName() string {
	if p.tableName != "" {
		return p.tableName
	}
	return "iam_auth_method"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (p *AuthMethod) SetTableName(n string) {
	if n != "" {
		p.tableName = n
	}
}
