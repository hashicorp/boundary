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

// RoleGrant defines the grants that are assigned to a role
type RoleGrant struct {
	*store.RoleGrant
	tableName string `gorm:"-"`
}

// ensure that RoleGrant implements the interfaces of: Resource, ClonableResource and db.VetForWriter
var _ Resource = (*RoleGrant)(nil)
var _ ClonableResource = (*RoleGrant)(nil)
var _ db.VetForWriter = (*RoleGrant)(nil)

// NewRoleGrant creates a new grant with a scope (project/organization)
// options include: withFriendlyName
func NewRoleGrant(primaryScope *Scope, role *Role, grant string, opt ...Option) (*RoleGrant, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts.withFriendlyName
	if primaryScope == nil {
		return nil, errors.New("error the role grant primary scope is nil")
	}
	if primaryScope.Type != OrganizationScope.String() &&
		primaryScope.Type != ProjectScope.String() {
		return nil, errors.New("role grants can only be within an organization or project scope")
	}
	if role == nil {
		return nil, errors.New("error role is nil")
	}
	if role.Id == 0 {
		return nil, errors.New("error role id == 0")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new role grant", err)
	}
	rg := &RoleGrant{
		RoleGrant: &store.RoleGrant{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			RoleId:         role.Id,
			Grant:          grant,
		},
	}
	if withFriendlyName != "" {
		rg.FriendlyName = withFriendlyName
	}
	return rg, nil
}

func allocRoleGrant() RoleGrant {
	return RoleGrant{
		RoleGrant: &store.RoleGrant{},
	}
}

// Clone creates a clone of the RoleGrant
func (g *RoleGrant) Clone() Resource {
	cp := proto.Clone(g.RoleGrant)
	return &RoleGrant{
		RoleGrant: cp.(*store.RoleGrant),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (g *RoleGrant) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if g.PublicId == "" {
		return errors.New("error public id is empty string for grant write")
	}
	if g.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for grant write")
	}
	// make sure the scope is valid for users
	if err := g.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (g *RoleGrant) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, g)
	if err != nil {
		return err
	}
	if ps.Type != OrganizationScope.String() && ps.Type != ProjectScope.String() {
		return errors.New("error primary scope is not an organization or project for the grant")
	}
	return nil
}

// GetPrimaryScope returns the PrimaryScope for the RoleGrant
func (g *RoleGrant) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, g)
}

// ResourceType returns the type of the RoleGrant
func (*RoleGrant) ResourceType() ResourceType { return ResourceTypeRoleGrant }

// Actions returns the  available actions for RoleGrant
func (*RoleGrant) Actions() map[string]Action {
	return StdActions()
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
