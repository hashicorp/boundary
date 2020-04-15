package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
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
func NewUser(s *Scope, opt ...Option) (*User, error) {
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
			PublicId:       publicId,
			PrimaryScopeId: s.Id,
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

// VetForWrite implements db.VetForWrite() interface
func (u *User) VetForWrite() error {
	if u.PublicId == "" {
		return errors.New("error public id is empty string for user Write")
	}
	if u.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for user Write")
	}
	if u.OwnerId == 0 && !u.isRootUser {
		return errors.New("error owner id is nil for user Write")
	}
	if u.isRootUser && u.OwnerId != 0 {
		return errors.New("error a root user cannot have an owner id")
	}
	return nil
}

// GetOwner returns
func (u *User) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	if u.Id == 0 {
		return nil, errors.New("error user id is 0")
	}
	if u.OwnerId == 0 {
		return nil, nil
	}
	owner := User{}
	if err := r.LookupById(ctx, &owner); err != nil {
		return nil, fmt.Errorf("error getting Owner %w for user", err)
	}
	return &owner, nil
}

// GetPrimaryScope returns the PrimaryScope for the User if there is one defined.
func (u *User) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for user GetPrimaryScope")
	}
	if u.PrimaryScopeId == 0 {
		return nil, errors.New("error primary scope is unset for user GetPrimaryScope")
	}
	var p Scope
	if err := r.LookupBy(ctx, &p, "id = ?", u.PrimaryScopeId); err != nil {
		return nil, fmt.Errorf("error getting PrimaryScope %w for User", err)
	}
	return &p, nil
}
func (u *User) GetAssignableScopes(ctx context.Context, r db.Reader) (map[string]*AssignableScope, error) {
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
