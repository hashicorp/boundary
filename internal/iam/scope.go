// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

const (
	defaultScopeTableName = "iam_scope"
)

// Scope is used to create a hierarchy of "containers" that encompass the scope of
// an IAM resource.  Scopes are Global, Orgs and Projects.
type Scope struct {
	*store.Scope

	StoragePolicyId string `json:"storage_policy_id,omitempty" gorm:"-"`

	// tableName which is used to support overriding the table name in the db
	// and making the Scope a ReplayableMessage
	tableName string `gorm:"-"`
}

// ensure that Scope implements the interfaces of: Resource, Cloneable, and db.VetForWriter
var (
	_ Resource        = (*Scope)(nil)
	_ db.VetForWriter = (*Scope)(nil)
	_ Cloneable       = (*Scope)(nil)
)

func NewOrg(ctx context.Context, opt ...Option) (*Scope, error) {
	global := AllocScope()
	global.PublicId = scope.Global.String()
	return newScope(ctx, &global, opt...)
}

func NewProject(ctx context.Context, orgPublicId string, opt ...Option) (*Scope, error) {
	const op = "iam.NewProject"
	org := AllocScope()
	org.PublicId = orgPublicId
	p, err := newScope(ctx, &org, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return p, nil
}

// newScope creates a new Scope with options: WithName specifies the Scope's
// friendly name. WithDescription specifies the scope's description. WithScope
// specifies the Scope's parent and must be filled in. The type of the parent is
// used to determine the type of the child. WithPrimaryAuthMethodId specifies
// the primary auth method for the scope
func newScope(ctx context.Context, parent *Scope, opt ...Option) (*Scope, error) {
	const op = "iam.newScope"
	if parent == nil || parent.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "child scope is missing its parent")
	}
	var typ scope.Type
	switch {
	case parent.PublicId == scope.Global.String():
		typ = scope.Org
	case strings.HasPrefix(parent.PublicId, scope.Org.Prefix()):
		typ = scope.Project
	}
	if typ == scope.Unknown {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown scope type")
	}

	opts := getOpts(opt...)
	s := &Scope{
		Scope: &store.Scope{
			Type:                typ.String(),
			Name:                opts.withName,
			Description:         opts.withDescription,
			ParentId:            parent.PublicId,
			PrimaryAuthMethodId: opts.withPrimaryAuthMethodId,
		},
	}

	return s, nil
}

func AllocScope() Scope {
	return Scope{
		Scope: &store.Scope{},
	}
}

// Clone creates a clone of the Scope
func (s *Scope) Clone() any {
	cp := proto.Clone(s.Scope)
	return &Scope{
		Scope: cp.(*store.Scope),
	}
}

// Oplog provides the oplog.Metadata for recording operations taken on a Scope.
func (s *Scope) Oplog(op oplog.OpType) oplog.Metadata {
	return oplog.Metadata{
		"resource-public-id": []string{s.PublicId},
		"resource-type":      []string{"scope"},
		"op-type":            []string{op.String()},
		"parent-id":          []string{s.ParentId},
	}
}

// VetForWrite implements db.VetForWrite() interface for scopes
// this function is intended to be callled by a db.Writer (Create and Update) to validate
// the scope before writing it to the db.
func (s *Scope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(Scope).VetForWrite"
	if s.Type == scope.Unknown.String() {
		return errors.New(ctx, errors.InvalidParameter, op, "unknown scope type")
	}
	if s.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if opType == db.UpdateOp {
		dbOptions := db.GetOpts(opt...)
		for _, path := range dbOptions.WithFieldMaskPaths {
			switch path {
			case "ParentId":
				return errors.New(ctx, errors.InvalidParameter, op, "you cannot change a scope's parent")
			case "Type":
				return errors.New(ctx, errors.InvalidParameter, op, "you cannot change a scope's type")
			}
		}
	}
	if opType == db.CreateOp {
		switch {
		case s.Type == scope.Global.String():
			return errors.New(ctx, errors.InvalidParameter, op, "you cannot create a global scope")
		case s.ParentId == "":
			return errors.New(ctx, errors.InvalidParameter, op, "scope must have a parent")
		case s.Type == scope.Org.String():
			if s.ParentId != scope.Global.String() {
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf(`org's parent must be "%s"`, scope.Global.String()))
			}
		case s.Type == scope.Project.String():
			parentScope := AllocScope()
			parentScope.PublicId = s.ParentId
			if err := r.LookupByPublicId(ctx, &parentScope, opt...); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to verify project's org scope"))
			}
			if parentScope.Type != scope.Org.String() {
				return errors.New(ctx, errors.InvalidParameter, op, "project parent scope is not an org")
			}
		}
	}
	return nil
}

// GetResourceType returns the type of scope
func (s *Scope) GetResourceType() resource.Type {
	return resource.Scope
}

// Actions returns the available actions for Scopes
func (*Scope) Actions() map[string]action.Type {
	return CrudlActions()
}

// GetScope returns the scope for the "scope" if there is one defined
func (s *Scope) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	const op = "iam.(Scope).GetScope"
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if s.PublicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if s.Type == "" && s.ParentId == "" {
		if err := r.LookupByPublicId(ctx, s); err != nil {
			return nil, errors.Wrap(ctx, err, op)
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
			if err := r.LookupWhere(ctx, &p, where, []any{s.PublicId}); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup parent public id from public id"))
			}
		default:
			if err := r.LookupWhere(ctx, &p, "public_id = ?", []any{s.ParentId}); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup parent from public id"))
			}
		}
		return &p, nil
	}
}

// GetStoragePolicyId returns the storage policy id attached to the scope
func (s *Scope) GetStoragePolicyId() string {
	return s.StoragePolicyId
}

// SetStoragePolicyId sets the storage policy id
func (s *Scope) SetStoragePolicyId(v string) {
	s.StoragePolicyId = v
}

// TableName returns the tablename to override the default gorm table name
func (s *Scope) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultScopeTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (s *Scope) SetTableName(n string) {
	s.tableName = n
}

type deletedScope struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedScope) TableName() string {
	return "iam_scope_deleted"
}
