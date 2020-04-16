package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

// Scope is used to create a hierarchy of "containers" that encompass the scope of
// an IAM resource.  Scopes are Organizations and Projects for launch and likely
// Folders and SubProjects in the future
type Scope struct {
	*store.Scope

	// tableName which is used to support overriding the table name in the db
	// and making the Scope a ReplayableMessage
	tableName string `gorm:"-"`
}

var _ Resource = (*Scope)(nil)

// NewScope creates a new Scope with options:
// WithOwnerId specifies the Scope's owner id (a User). Most Scopes
// will have an owner id, but we have to be able to create Scopes before users.
// WithFriendlyName specifies the Scope's friendly name.
func NewScope(opt ...Option) (*Scope, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	withOwnerId := opts[optionWithOwnerId].(uint32)
	withScope := opts[optionWithScope]

	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new scope", err)
	}
	s := &Scope{
		Scope: &store.Scope{
			PublicId: publicId,
		},
	}
	if withScope != nil {
		parentScope, ok := withScope.(*Scope)
		if !ok {
			return nil, errors.New("error assigning scope parent id to primary scope that is not a scope")
		}
		if parentScope.Id == 0 {
			return nil, errors.New("error assigning scope parent id to primary scope with id == 0")
		}
		s.ParentId = parentScope.Id
	}
	if withOwnerId != 0 {
		s.OwnerId = withOwnerId
	}
	if withFriendlyName != "" {
		s.FriendlyName = withFriendlyName
	}
	return s, nil
}

// VetForWrite implements db.VetForWrite() interface
func (s *Scope) VetForWrite() error {
	if s.PublicId == "" {
		return errors.New("error public id is empty string for scope write")
	}
	return nil
}
func (s *Scope) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	return LookupOwner(ctx, r, s)
}
func (s *Scope) ResourceType() ResourceType { return ResourceTypeScope }

func (*Scope) Actions() map[string]Action {
	return StdActions()
}
func (s *Scope) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for scope getting primary scope")
	}
	if s.ParentId == 0 {
		return nil, nil
	}
	var p Scope
	if err := r.LookupBy(ctx, &p, "id = ?", s.ParentId); err != nil {
		return nil, fmt.Errorf("error getting primary scope %w for scope", err)
	}
	return &p, nil
}

func (s *Scope) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "iam_scope"
}

func (s *Scope) SetTableName(n string) {
	if n != "" {
		s.tableName = n
	}
}
