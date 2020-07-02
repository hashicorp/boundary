package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/perms"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
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
func NewRoleGrant(roleId string, grant string, opt ...Option) (*RoleGrant, error) {
	if roleId == "" {
		return nil, fmt.Errorf("new role grant: role id is not set: %w", db.ErrNilParameter)
	}
	rg := &RoleGrant{
		RoleGrant: &store.RoleGrant{
			RoleId:    roleId,
			UserGrant: grant,
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
	if g.PrivateId == "" {
		return fmt.Errorf("private id is empty string for grant write: %w", db.ErrInvalidParameter)
	}

	// Validate that the grant parses successfully. Note that we fake the scope
	// here to avoid a lookup as the scope is only relevant at actual ACL
	// checking time and we just care that it parses correctly.
	perm, err := perms.Parse(
		perms.Scope{
			Id:   "s_abcd1234",
			Type: scope.Organization,
		},
		"",
		g.UserGrant,
	)
	if err != nil {
		return fmt.Errorf("vet role grant for writing: error parsing grant string: %w", err)
	}
	g.CanonicalGrant = perm.CanonicalString()

	return nil
}

// ResourceType returns the type of the RoleGrant
func (*RoleGrant) ResourceType() resource.Type { return resource.RoleGrant }

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
