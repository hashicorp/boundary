package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
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

func NewScope(ownerId uint32, opt ...Option) (*Scope, error) {
	if ownerId == 0 {
		return nil, errors.New("error ownerId is 0 for NewScope")
	}
	// we intentionally don't check for ownerID
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)

	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public ID %w for NewScope", err)
	}
	s := &Scope{
		Scope: &store.Scope{
			PublicId: publicId,
			OwnerId:  ownerId,
		},
	}
	if withFriendlyName != "" {
		s.FriendlyName = withFriendlyName
	}
	return s, nil
}
func (s *Scope) Write(ctx context.Context, w Writer) error {
	if w == nil {
		return errors.New("error writer is nil for scope Write")
	}
	if s.PublicId == "" {
		return errors.New("error public id is empty string for scope Write")
	}
	if s.OwnerId == 0 {
		return errors.New("error owner id is 0 for scope Write")
	}
	return w.Create(ctx, s)
}

func (*Scope) GetOwner(ctx context.Context, r Reader) (*User, error) {
	return nil, nil
}
func (s *Scope) ResourceType() ResourceType { return ResourceTypeScope }

func (*Scope) Actions() map[string]Action {
	return StdActions()
}
func (s *Scope) GetPrimaryScope(ctx context.Context, r Reader) (*Scope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for scope GetPrimaryScope")
	}
	if s.ParentId == 0 {
		return nil, nil
	}
	var p Scope
	if err := r.LookupBy(ctx, &p, "public_id = ?", s.ParentId); err != nil {
		return nil, fmt.Errorf("error getting PrimaryScope %w for Scope", err)
	}
	return &p, nil
}
func (s *Scope) GetAssignableScopes(ctx context.Context, r Reader) (map[string]*AssignableScope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for GetAssignableScopes")
	}
	as := []*AssignableScope{}
	if err := r.SearchBy(ctx, as, "primary_scope_id = ?", s.Id); err != nil {
		return nil, fmt.Errorf("error getting AssignableScopes %w for Scope", err)
	}
	asmap := map[string]*AssignableScope{}
	for _, s := range as {
		asmap[s.PublicId] = s
	}
	return asmap, nil
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
