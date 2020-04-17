package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

// UserAlias are the aliases attached to users based on the AuthMethod used for the Alias
type UserAlias struct {
	*store.UserAlias
	tableName string `gorm:"-"`
}

var _ Resource = (*UserAlias)(nil)

var _ db.VetForWriter = (*UserAlias)(nil)

// NewUserAlias creates a new user alias for scope (project/organization), owner (user), and auth method
func NewUserAlias(primaryScope *Scope, owner *User, authMethod *AuthMethod, opt ...Option) (*UserAlias, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if primaryScope == nil {
		return nil, errors.New("error user alias primary scope is nil")
	}
	if owner == nil {
		return nil, errors.New("error the user alias owner is nil")
	}
	if owner.Id == 0 {
		return nil, errors.New("error the user alias owner id == 0")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("user aliases can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public ID %w for new user alias", err)
	}
	a := &UserAlias{
		UserAlias: &store.UserAlias{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			OwnerId:        owner.OwnerId,
		},
	}
	if withFriendlyName != "" {
		a.FriendlyName = withFriendlyName
	}
	return a, nil
}

// VetForWrite implements db.VetForWrite() interface
func (a *UserAlias) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if a.PublicId == "" {
		return errors.New("error public id is empty string for user write")
	}
	if a.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for user write")
	}
	if a.OwnerId == 0 {
		return errors.New("error owner id is nil for user write")
	}
	// make sure the scope is valid for aliases
	if err := a.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

// primaryScopeIsValid checks the alias primary scope to make sure it's either an org or project
func (a *UserAlias) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, a)
	if err != nil {
		return err
	}
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization")
	}
	return nil
}

// GetOwner returns the owner (User) of the UserAlias
func (a *UserAlias) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	return LookupOwner(ctx, r, a)
}

// GetPrimaryScope returns the PrimaryScope for the UserAlias
func (a *UserAlias) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, a)
}

// ResourceType returns the type of the UserAlias
func (*UserAlias) ResourceType() ResourceType { return ResourceTypeUserAlias }

// Actions returns the  available actions for UserAliases which are unique since then can authen
func (*UserAlias) Actions() map[string]Action {
	actions := StdActions()
	actions[ActionAuthen.String()] = ActionAuthen
	return actions
}

// TableName returns the tablename to override the default gorm table name
func (a *UserAlias) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return "iam_user_alias"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (a *UserAlias) SetTableName(n string) {
	if n != "" {
		a.tableName = n
	}
}
