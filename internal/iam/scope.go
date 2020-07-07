package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

// Scope is used to create a hierarchy of "containers" that encompass the scope of
// an IAM resource.  Scopes are Global, Organizations and Projects.
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
	global := allocScope()
	global.PublicId = "global"
	opt = append(opt, withScope(&global))
	return newScope(scope.Organization, opt...)
}

func NewProject(organizationPublicId string, opt ...Option) (*Scope, error) {
	org := allocScope()
	org.PublicId = organizationPublicId
	opt = append(opt, withScope(&org))
	p, err := newScope(scope.Project, opt...)
	if err != nil {
		return nil, fmt.Errorf("error creating new project: %w", err)
	}
	return p, nil
}

// newScope creates a new Scope of the specified ScopeType with options:
// WithName specifies the Scope's friendly name. WithDescription specifies the
// scope's description. WithScope specifies the Scope's parent
func newScope(scopeType scope.Type, opt ...Option) (*Scope, error) {
	opts := getOpts(opt...)
	switch scopeType {
	case scope.Unknown:
		return nil, fmt.Errorf("new scope: unknown scope type: %w", db.ErrInvalidParameter)
	case scope.Global:
		return nil, fmt.Errorf("new scope: invalid scope type: %w", db.ErrInvalidParameter)
	default:
		if opts.withScope == nil {
			return nil, fmt.Errorf("new scope: child scope is missing its parent: %w", db.ErrInvalidParameter)
		}
		if opts.withScope.PublicId == "" {
			return nil, fmt.Errorf("new scope: with scope's parent id is missing: %w", db.ErrInvalidParameter)
		}
	}

	s := &Scope{
		Scope: &store.Scope{
			Type:        scopeType.String(),
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	if opts.withScope != nil {
		s.ParentId = opts.withScope.PublicId
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
	if s.Type == scope.Unknown.String() {
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
		switch {
		case s.Type == scope.Global.String():
			return errors.New("global scope cannot be created")
		case s.ParentId == "":
			switch s.Type {
			case scope.Organization.String():
				return errors.New("organization must have global parent")
			case scope.Project.String():
				return errors.New("project has no organization")
			}
		case s.Type == scope.Organization.String():
			if s.ParentId != "global" {
				return errors.New(`organization's parent must be "global"`)
			}
		case s.Type == scope.Project.String():
			parentScope := allocScope()
			parentScope.PublicId = s.ParentId
			if err := r.LookupByPublicId(ctx, &parentScope, opt...); err != nil {
				return fmt.Errorf("unable to verify project's organization scope: %w", err)
			}
			if parentScope.Type != scope.Organization.String() {
				return errors.New("project parent scope is not an organization")
			}
		}
	}
	return nil
}

// ResourceType returns the type of scope
func (s *Scope) ResourceType() resource.Type {
	switch s.Type {
	case scope.Global.String():
		return resource.Global
	case scope.Organization.String():
		return resource.Organization
	case scope.Project.String():
		return resource.Project
	default:
		return resource.Scope
	}
}

// Actions returns the  available actions for Scopes
func (*Scope) Actions() map[string]action.Type {
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
	// HANDLE_GLOBAL
	switch s.Type {
	case scope.Global.String():
		return nil, nil
	default:
		var p Scope
		switch s.ParentId {
		case "":
			// no parent id, so use the public_id to find the parent scope. This
			// won't work for if the scope hasn't been written to the db yet,
			// like during create but in that case the parent id should be set
			// for all scopes which are not global, and the global case was
			// handled at HANDLE_GLOBAL
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
