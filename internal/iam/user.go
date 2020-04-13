package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

type User struct {
	*store.User
	tableName  string `gorm:"-"`
	isRootUser bool   `gorm:"-"`
}

var _ Resource = (*User)(nil)

// NewUser creates a new user and allows options:
// WithOwnerId - to specify the user's owner id (another user)
// AsRootUser - to specify a root user with no owner (null)
// withFriendlyName - to specify the user's friendly name
func NewUser(opt ...Option) (*User, error) {
	// we intentionally don't check for ownerID
	opts := GetOpts(opt...)
	asRootUser := opts[optionAsRootUser].(bool)
	withOwnerId := opts[optionWithOwnerId].(uint32)
	withFriendlyName := opts[optionWithFriendlyName].(string)

	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public ID %w for NewUser", err)
	}
	u := &User{
		User: &store.User{
			PublicId: publicId,
		},
	}
	if asRootUser {
		u.isRootUser = true
	}
	if withOwnerId != 0 {
		u.OwnerId = withOwnerId
	}
	if withOwnerId != 0 && asRootUser {
		return nil, errors.New("error a root user cannot have an owner id")
	}
	if withFriendlyName != "" {
		u.FriendlyName = withFriendlyName
	}
	return u, nil
}
func (u *User) Write(ctx context.Context, w Writer) error {
	if u.PublicId == "" {
		return errors.New("error public id is empty string for user Write")
	}
	if u.OwnerId == 0 && !u.isRootUser {
		return errors.New("error owner id is nil for user Write")
	}
	if u.isRootUser && u.OwnerId != 0 {
		return errors.New("error a root user cannot have an owner id")
	}
	if err := w.Create(ctx, u); err != nil {
		return err
	}
	return nil
}

func (u *User) GetOwner(ctx context.Context, r Reader) (*User, error) {
	return nil, nil
}
func (u *User) GetPrimaryScope(ctx context.Context, r Reader) (*Scope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for user GetPrimaryScope")
	}
	// if u.PrimaryScopeId != nil && u.PrimaryScopeId.Value != 0 {
	if u.PrimaryScopeId != 0 {
		return nil, nil
	}
	var p Scope
	if err := r.LookupBy(ctx, &p, "id = ?", u.PrimaryScopeId); err != nil {
		return nil, fmt.Errorf("error getting PrimaryScope %w for User", err)
	}
	return &p, nil
}
func (u *User) GetAssignableScopes(ctx context.Context, r Reader) (map[string]*AssignableScope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for AssignableScopes for User")
	}
	as := []*AssignableScope{}
	if err := r.SearchBy(ctx, as, "primary_scope_id = ?", u.Id); err != nil {
		return nil, fmt.Errorf("error getting PrimaryScope %w for User", err)
	}
	asmap := map[string]*AssignableScope{}
	for _, s := range as {
		asmap[s.PublicId] = s
	}
	return asmap, nil
}
func (*User) ResourceType() ResourceType { return ResourceTypeUser }

func (*User) Actions() map[string]Action {
	return StdActions()
}
func (u *User) TableName() string {
	if u.tableName != "" {
		return u.tableName
	}
	return "iam_user"
}

func (u *User) SetTableName(n string) {
	if n != "" {
		u.tableName = n
	}
}
