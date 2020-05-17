package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

// ensure that Scope implements the interfaces of: Resource, Clonable, and db.VetForWriter
var _ Resource = (*Scope)(nil)
var _ db.VetForWriter = (*Scope)(nil)
var _ Clonable = (*Scope)(nil)

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
	withPublicId := opts.withPublicId
	withName := opts.withName
	withScope := opts.withScope
	withDescription := opts.withDescription

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
	prefix := "p"
	if scopeType == OrganizationScope {
		prefix = "o"
	}
	var publicId string
	if withPublicId != "" {
		if !strings.HasPrefix(withPublicId, prefix+"_") {
			return nil, errors.New("passed-in public ID has wrong prefix for type")
		}
		publicId = withPublicId
	} else {
		var err error
		publicId, err = db.NewPublicId(prefix)
		if err != nil {
			return nil, fmt.Errorf("error generating public id %w for new scope", err)
		}
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
	if withDescription != "" {
		s.Description = withDescription
	}
	return s, nil
}

func allocScope() Scope {
	return Scope{
		Scope: &store.Scope{},
	}
}

// Clone creates a clone of the Scope
func (s *Scope) Clone() interface{} {
	cp := proto.Clone(s.Scope)
	return &Scope{
		Scope: cp.(*store.Scope),
	}
}

// VetForWrite implements db.VetForWrite() interface for scopes
// this function is intended to be callled by a db.Writer (Create and Update) to validate
// the scope before writing it to the db.
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
	switch s.Type {
	case OrganizationScope.String():
		return ResourceTypeOrganization
	case ProjectScope.String():
		return ResourceTypeProject
	default:
		return ResourceTypeScope
	}
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
	if s.PublicId == "" {
		return nil, errors.New("unable to get scope with unset public id")
	}
	if s.Type == "" && s.ParentId == "" {
		if err := r.LookupByPublicId(ctx, s); err != nil {
			return nil, fmt.Errorf("unable to get scope by public id: %w", err)
		}
	}
	// HANDLE_ORG
	if s.Type == OrganizationScope.String() {
		return nil, nil
	}
	if s.Type == ProjectScope.String() {
		var p Scope
		switch s.ParentId {
		case "":
			// no parent id, so use the public_id to find the parent scope. This
			// won't work for if the scope hasn't been written to the db yet,
			// like during create but in that case the parent id should be set
			// for all scopes which are not organizations, and the organization
			// case was handled at HANDLE_ORG
			where := "public_id in (select parent_id from iam_scope where public_id = ?)"
			if err := r.LookupWhere(ctx, &p, where, s.PublicId); err != nil {
				return nil, fmt.Errorf("unable to lookup parent public id from public id: %w", err)
			}
		default:
			if err := r.LookupWhere(ctx, &p, "public_id = ?", s.ParentId); err != nil {
				return nil, fmt.Errorf("unable to lookup parent from public id: %w", err)
			}
		}
		return &p, nil
	}
	return nil, fmt.Errorf("unable to get scope with type %s", s.Type)
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
