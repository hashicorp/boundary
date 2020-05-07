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
// an IAM resource.  Scopes are Organizations and Projects.
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

func NewOrganization(opt ...Option) (*Scope, error) {
	return newScope(OrganizationScope, opt...)
}

func NewProject(organizationPublicId string, opt ...Option) (*Scope, error) {
	org := allocScope()
	org.PublicId = organizationPublicId
	opt = append(opt, withScope(&org))
	p, err := newScope(ProjectScope, opt...)
	if err != nil {
		return nil, fmt.Errorf("error creating new project: %w", err)
	}
	return p, nil
}

// newScope creates a new Scope of the specified ScopeType with options:
// WithName specifies the Scope's friendly name.
// WithScope specifies the Scope's parent
func newScope(scopeType ScopeType, opt ...Option) (*Scope, error) {
	opts := getOpts(opt...)
	withName := opts.withName
	withScope := opts.withScope

	if scopeType == UnknownScope {
		return nil, errors.New("error unknown scope type for new scope")
	}
	if scopeType == ProjectScope {
		if withScope == nil {
			return nil, errors.New("error project scope must be with a scope")
		}
		if withScope.PublicId == "" {
			return nil, errors.New("error project scope parent id is unset")
		}
	}
	publicId, err := base62.Random(32)
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
			return nil, errors.New("error assigning scope parent id to a scope with unset id")
		}
		s.ParentId = withScope.PublicId
	}
	if withName != "" {
		s.Name = withName
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

// VetForWrite implements db.VetForWrite() interface for scopes
func (s *Scope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if s.Type == UnknownScope.String() {
		return errors.New("unknown scope type for scope write")
	}
	if s.PublicId == "" {
		return errors.New("public id is empty string for scope write")
	}
	if opType == db.UpdateOp {
		dbOptions := db.GetOpts(opt...)
		for _, path := range dbOptions.WithFieldMaskPaths {
			switch path {
			case "ParentId":
				return errors.New("you cannot change a scope's parent")
			case "Type":
				return errors.New("you cannot change a scope's type")
			}
		}
	}
	if opType == db.CreateOp {
		if s.ParentId == "" && s.Type == ProjectScope.String() {
			return errors.New("project has no organization")
		}
		if s.Type == ProjectScope.String() {
			parentScope := allocScope()
			parentScope.PublicId = s.ParentId
			if err := r.LookupByPublicId(ctx, &parentScope, opt...); err != nil {
				return fmt.Errorf("unable to verify project's organization scope: %w", err)
			}
			if parentScope.Type != OrganizationScope.String() {
				return errors.New("project parent scope is not an organization")
			}
		}
	}
	return nil
}

// ResourceType returns the type of scope
func (s *Scope) ResourceType() ResourceType {
	if s.Type == OrganizationScope.String() {
		return ResourceTypeOrganization
	}
	if s.Type == ProjectScope.String() {
		return ResourceTypeProject
	}
	return ResourceTypeScope
}

// Actions returns the  available actions for Scopes
func (*Scope) Actions() map[string]Action {
	return CrudActions()
}

// GetScope returns the scope for the "scope" if there is one defined
func (s *Scope) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	if r == nil {
		return nil, errors.New("error db is nil for get scope")
	}
	if s.ParentId == "" {
		return nil, nil
	}
	var p Scope
	if err := r.LookupWhere(ctx, &p, "public_id = ?", s.ParentId); err != nil {
		return nil, fmt.Errorf("error getting scope %w", err)
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
