package iam

import (
	"context"
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

// ensure that User implements the interfaces of: Resource, Clonable and db.VetForWriter
var _ Resource = (*User)(nil)
var _ Clonable = (*User)(nil)
var _ db.VetForWriter = (*User)(nil)

// NewUser creates a new in memory user and allows options:
// WithName - to specify the user's friendly name and WithDescription - to
// specify a user description
func NewUser(organizationPublicId string, opt ...Option) (*User, error) {
	opts := getOpts(opt...)
	if organizationPublicId == "" {
		return nil, fmt.Errorf("new user: missing organization id %w", db.ErrInvalidParameter)
	}
	u := &User{
		User: &store.User{
			Name:        opts.withName,
			Description: opts.withDescription,
			ScopeId:     organizationPublicId,
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

// VetForWrite implements db.VetForWrite() interface and validates the user
// before it's written.
func (u *User) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if u.PublicId == "" {
		return fmt.Errorf("user vet for write: missing public id: %w", db.ErrNilParameter)
	}
	if err := validateScopeForWrite(ctx, r, u, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (u *User) validScopeTypes() []ScopeType {
	return []ScopeType{OrganizationScope}
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

const UserPrefix = "u"

func newUserId() (string, error) {
	id, err := db.NewPublicId(UserPrefix)
	if err != nil {
		return "", fmt.Errorf("new user id: %w", err)
	}
	return id, nil
}
