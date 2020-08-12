package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
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
var _ Resource = (*Group)(nil)
var _ Cloneable = (*Group)(nil)
var _ db.VetForWriter = (*Group)(nil)

// NewGroup creates a new in memory group with a scope (project/org)
// and allowed options include: withDescripion, WithName.
func NewGroup(scopeId string, opt ...Option) (*Group, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new group: missing scope id %w", db.ErrInvalidParameter)
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
func (g *Group) Clone() interface{} {
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
	if g.PublicId == "" {
		return fmt.Errorf("group vet for write: missing public id: %w", db.ErrInvalidParameter)
	}
	if err := validateScopeForWrite(ctx, r, g, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (u *Group) validScopeTypes() []scope.Type {
	return []scope.Type{scope.Global, scope.Org, scope.Project}
}

// GetScope returns the scope for the Group.
func (g *Group) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, g)
}

// ResourceType returns the type of the Group.
func (*Group) ResourceType() resource.Type { return resource.Group }

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
