package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// User defines watchtower users which are scoped to an Organization
type User struct {
	*store.User
	tableName string `gorm:"-"`
}

// ensure that User implements the interfaces of: Resource, ClonableResource and db.VetForWriter
var _ Resource = (*User)(nil)
var _ Clonable = (*User)(nil)
var _ db.VetForWriter = (*User)(nil)

// NewUser creates a new in memory user and allows options:
// WithName - to specify the user's friendly name
func NewUser(organizationPublicId string, opt ...Option) (*User, error) {
	opts := getOpts(opt...)
	withName := opts.withName
	if organizationPublicId == "" {
		return nil, errors.New("error organization id is unset for new user")
	}
	publicId, err := db.NewPublicId("u")
	if err != nil {
		return nil, fmt.Errorf("error generating public ID %w for new user", err)
	}
	u := &User{
		User: &store.User{
			PublicId: publicId,
			Name:     withName,
			ScopeId:  organizationPublicId,
		},
	}
	return u, nil
}

func allocUser() User {
	return User{
		User: &store.User{},
	}
}

// Clone creates a clone of the User
func (u *User) Clone() interface{} {
	cp := proto.Clone(u.User)
	return &User{
		User: cp.(*store.User),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (u *User) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if u.PublicId == "" {
		return errors.New("error public id is empty string for user write")
	}
	if u.ScopeId == "" {
		return errors.New("error scope id not set for user write")
	}
	// make sure the scope is valid for users
	if err := u.scopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (u *User) scopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupScope(ctx, r, u)
	if err != nil {
		return err
	}
	if ps.Type != OrganizationScope.String() {
		return errors.New("error scope is not an organization")
	}
	return nil
}

// GetScope returns the scope for the User
func (u *User) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, u)
}

// ResourceType returns the type of the User
func (*User) ResourceType() ResourceType { return ResourceTypeUser }

// Actions returns the  available actions for Users
func (*User) Actions() map[string]Action {
	return CrudActions()
}

// TableName returns the tablename to override the default gorm table name
func (u *User) TableName() string {
	if u.tableName != "" {
		return u.tableName
	}
	return "iam_user"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (u *User) SetTableName(n string) {
	if n != "" {
		u.tableName = n
	}
}
