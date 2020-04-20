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

// NewUserAlias creates a new user alias with a given name for
// a scope (project/organization), owner (user), and auth method
func NewUserAlias(primaryScope *Scope, owner *User, authMethod *AuthMethod, name string, opt ...Option) (*UserAlias, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if name == "" {
		return nil, errors.New("error user alias name is null")
	}
	if authMethod.Id == 0 {
		return nil, errors.New("error user alias auth method id == 0")
	}
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
			Name:           name,
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			OwnerId:        owner.Id,
			AuthMethodId:   authMethod.Id,
		},
	}
	if withFriendlyName != "" {
		a.FriendlyName = withFriendlyName
	}
	return a, nil
}

// VetForWrite implements db.VetForWrite() interface
func (a *UserAlias) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if a.Name == "" {
		return errors.New("error alias name is null for user alias write")
	}
	if a.AuthMethodId == 0 {
		return errors.New("error auth method id ==0 for user alias write")
	}
	if a.PublicId == "" {
		return errors.New("error public id is empty string for user alias write")
	}
	if a.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for user alias write")
	}
	if a.OwnerId == 0 {
		return errors.New("error owner id is nil for user alias write")
	}
	// make sure the scope is valid for aliases
	if err := a.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

// Groups searches for all the UserAlias' groups
func (u *UserAlias) Groups(ctx context.Context, r db.Reader) ([]*Group, error) {
	if u.Id == 0 {
		return nil, errors.New("error user id is 0 for finding user alias groups")
	}
	where := "id in (select distinct group_id from iam_group_member where member_id = ? and type = ?)"
	groups := []*Group{}
	if err := r.SearchBy(ctx, &groups, where, u.Id, UserAliasMemberType); err != nil {
		return nil, fmt.Errorf("error finding user alias groups: %w", err)
	}
	return groups, nil
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
