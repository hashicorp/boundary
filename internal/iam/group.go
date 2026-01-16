// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const (
	defaultGroupTableName = "iam_group"
)

// Group is made up of principals which are scoped to an org.
type Group struct {
	*store.Group
	tableName string `gorm:"-"`
}

// ensure that Group implements the interfaces of: Resource, Cloneable, and db.VetForWriter.
var (
	_ Resource        = (*Group)(nil)
	_ Cloneable       = (*Group)(nil)
	_ db.VetForWriter = (*Group)(nil)
)

// NewGroup creates a new in memory group with a scope (project/org)
// and allowed options include: withDescription, WithName.
func NewGroup(ctx context.Context, scopeId string, opt ...Option) (*Group, error) {
	const op = "iam.NewGroup"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)
	g := &Group{
		Group: &store.Group{
			Name:        opts.withName,
			Description: opts.withDescription,
			ScopeId:     scopeId,
		},
	}
	return g, nil
}

// Clone creates a clone of the Group.
func (g *Group) Clone() any {
	cp := proto.Clone(g.Group)
	return &Group{
		Group: cp.(*store.Group),
	}
}

func allocGroup() Group {
	return Group{
		Group: &store.Group{},
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the group
// before it's written.
func (g *Group) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(Group).VetForWrite"
	if g.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, g, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (g *Group) getResourceType() resource.Type {
	return resource.Group
}

// GetScope returns the scope for the Group.
func (g *Group) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, g)
}

// GetResourceType returns the type of the Group.
func (*Group) GetResourceType() resource.Type { return resource.Group }

// Actions returns the  available actions for Group
func (*Group) Actions() map[string]action.Type {
	return CrudActions()
}

// TableName returns the tablename to override the default gorm table name.
func (g *Group) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultGroupTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (g *Group) SetTableName(n string) {
	g.tableName = n
}

type deletedGroup struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (u *deletedGroup) TableName() string {
	return "iam_group_deleted"
}
