package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// ScopeType defines the possible types for Scopes
type ScopeType uint32

const (
	UnknownScope      ScopeType = 0
	OrganizationScope ScopeType = 1
	ProjectScope      ScopeType = 2
)

func (s ScopeType) String() string {
	return [...]string{
		"unknown",
		"organization",
		"project",
	}[s]
}

// Scope is used to create a hierarchy of "containers" that encompass the scope of
// an IAM resource.  Scopes are Organizations and Projects (based on their Type) for
// launch and likely Folders and SubProjects in the future
type Scope struct {
	*store.Scope

	// tableName which is used to support overriding the table name in the db
	// and making the Scope a ReplayableMessage
	tableName string `gorm:"-"`
}

// ensure that Scope implements the interfaces of: Resource, ClonableResource, and db.VetForWriter
var _ Resource = (*Scope)(nil)
var _ db.VetForWriter = (*Scope)(nil)
var _ ClonableResource = (*Scope)(nil)

// NewScope creates a new Scope of the specified ScopeType with options:
// WithFriendlyName specifies the Scope's friendly name.
func NewScope(scopeType ScopeType, opt ...Option) (*Scope, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts.withFriendlyName
	withScope := opts.withScope

	if scopeType == UnknownScope {
		return nil, errors.New("error unknown scope type for new scope")
	}
	if scopeType == ProjectScope {
		if withScope == nil {
			return nil, errors.New("error project scope must be with a scope")
		}
		if withScope == nil {
			return nil, errors.New("error project scope with a nil scope")
		}
		if withScope.PublicId == "" {
			return nil, errors.New("error project scope parent id is unset")
		}
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new scope", err)
	}
	s := &Scope{
		Scope: &store.Scope{
			PublicId: publicId,
			Type:     scopeType.String(),
		},
	}
	if withScope != nil {
		if withScope.PublicId == "" {
			return nil, errors.New("error assigning scope parent id to primary scope with unset id")
		}
		s.ParentId = withScope.PublicId
	}
	if withFriendlyName != "" {
		s.FriendlyName = withFriendlyName
	}
	return s, nil
}

func allocScope() Scope {
	return Scope{
		Scope: &store.Scope{},
	}
}

// Clone creates a clone of the Scope
func (s *Scope) Clone() Resource {
	cp := proto.Clone(s.Scope)
	return &Scope{
		Scope: cp.(*store.Scope),
	}
}

// Organization will walk up the scope tree via primary scopes until it finds an organization
func (s *Scope) Organization(ctx context.Context, r db.Reader) (*Scope, error) {
	if s.Type == OrganizationScope.String() {
		return s, nil
	}
	p, err := s.GetPrimaryScope(ctx, r)
	if err != nil {
		return nil, err
	}
	if p.Type == OrganizationScope.String() {
		return p, nil
	}
	return p.Organization(ctx, r)
}

// VetForWrite implements db.VetForWrite() interface for scopes
func (s *Scope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if s.Type == UnknownScope.String() {
		return errors.New("error unknown scope type for scope write")
	}
	if s.PublicId == "" {
		return errors.New("error public id is empty string for scope write")
	}
	return nil
}

// ResourceType returns the type of resource
func (s *Scope) ResourceType() ResourceType { return ResourceTypeScope }

// Actions returns the  available actions for Scopes
func (*Scope) Actions() map[string]Action {
	return StdActions()
}

// GetPrimaryScope returns the primary scope for the scope if there is one defined
func (s *Scope) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for scope getting primary scope")
	}
	if s.ParentId == "" {
		return nil, nil
	}
	var p Scope
	if err := r.LookupBy(ctx, &p, "public_id = ?", s.ParentId); err != nil {
		return nil, fmt.Errorf("error getting primary scope %w for scope", err)
	}
	return &p, nil
}

// TableName returns the tablename to override the default gorm table name
func (s *Scope) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "iam_scope"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (s *Scope) SetTableName(n string) {
	if n != "" {
		s.tableName = n
	}
}
