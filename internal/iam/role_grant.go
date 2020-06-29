package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// RoleGrant defines the grants that are assigned to a role
type RoleGrant struct {
	*store.RoleGrant
	tableName string `gorm:"-"`
}

// ensure that RoleGrant implements the interfaces of: Clonable and db.VetForWriter
var _ Clonable = (*RoleGrant)(nil)
var _ db.VetForWriter = (*RoleGrant)(nil)

// NewRoleGrant creates a new in memory role grant
// options include: WithName
func NewRoleGrant(role *Role, grant string, opt ...Option) (*RoleGrant, error) {
	if role == nil {
		return nil, errors.New("error role is nil")
	}
	if role.PublicId == "" {
		return nil, errors.New("error role id is unset")
	}
	publicId, err := db.NewPublicId("rg")
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new role grant", err)
	}
	rg := &RoleGrant{
		RoleGrant: &store.RoleGrant{
			PublicId: publicId,
			RoleId:   role.PublicId,
			Grant:    grant,
		},
	}
	return rg, nil
}

func allocRoleGrant() RoleGrant {
	return RoleGrant{
		RoleGrant: &store.RoleGrant{},
	}
}

// Clone creates a clone of the RoleGrant
func (g *RoleGrant) Clone() interface{} {
	cp := proto.Clone(g.RoleGrant)
	return &RoleGrant{
		RoleGrant: cp.(*store.RoleGrant),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (g *RoleGrant) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if g.PublicId == "" {
		return errors.New("error public id is empty string for grant write")
	}
	return nil
}

// GetScope returns the scope for the RoleGrant
func (g *RoleGrant) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	if g.RoleId == "" {
		return nil, errors.New("grant's role id is unset")
	}
	role := allocRole()
	role.PublicId = g.RoleId
	if err := r.LookupByPublicId(ctx, &role); err != nil {
		return nil, fmt.Errorf("unable to look up grant's role: %w", err)
	}
	roleScope, err := LookupScope(ctx, r, &role)
	if err != nil {
		return nil, fmt.Errorf("unable to get grant's scope: %w", err)
	}
	return roleScope, nil
}

// ResourceType returns the type of the RoleGrant
func (*RoleGrant) ResourceType() resource.Type { return resource.RoleGrant }

// Actions returns the  available actions for RoleGrant
func (*RoleGrant) Actions() map[string]action.Type {
	return CrudActions()
}

// TableName returns the tablename to override the default gorm table name
func (g *RoleGrant) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return "iam_role_grant"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (g *RoleGrant) SetTableName(n string) {
	if n != "" {
		g.tableName = n
	}
}
