package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/perms"
	"google.golang.org/protobuf/proto"
)

const defaultRoleGrantTable = "iam_role_grant"

// RoleGrant defines the grants that are assigned to a role
type RoleGrant struct {
	*store.RoleGrant
	tableName string `gorm:"-"`
}

// ensure that RoleGrant implements the interfaces of: Cloneable and db.VetForWriter
var _ Cloneable = (*RoleGrant)(nil)
var _ db.VetForWriter = (*RoleGrant)(nil)

// NewRoleGrant creates a new in memory role grant
func NewRoleGrant(roleId string, grant string, opt ...Option) (*RoleGrant, error) {
	if roleId == "" {
		return nil, fmt.Errorf("new role grant: role id is not set: %w", db.ErrInvalidParameter)
	}
	if grant == "" {
		return nil, fmt.Errorf("new role grant: grant is empty: %w", db.ErrInvalidParameter)
	}

	// Validate that the grant parses successfully. Note that we fake the scope
	// here to avoid a lookup as the scope is only relevant at actual ACL
	// checking time and we just care that it parses correctly.
	perm, err := perms.Parse("o_abcd1234", grant)
	if err != nil {
		return nil, fmt.Errorf("new role grant: error parsing grant string: %w", err)
	}
	rg := &RoleGrant{
		RoleGrant: &store.RoleGrant{
			RoleId:         roleId,
			RawGrant:       grant,
			CanonicalGrant: perm.CanonicalString(),
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
	if g.RawGrant == "" {
		return fmt.Errorf("vet role grant for writing: grant is empty: %w", db.ErrInvalidParameter)
	}

	// Validate that the grant parses successfully. Note that we fake the scope
	// here to avoid a lookup as the scope is only relevant at actual ACL
	// checking time and we just care that it parses correctly. We may have
	// already done this in NewRoleGrant, but we re-check and set it here
	// anyways because it should still be part of the vetting process.
	perm, err := perms.Parse("o_abcd1234", g.RawGrant)
	if err != nil {
		return fmt.Errorf("vet role grant for writing: error parsing grant string: %w", err)
	}
	canonical := perm.CanonicalString()
	if g.CanonicalGrant != "" && g.CanonicalGrant != canonical {
		return fmt.Errorf("vet role grant for writing: existing canonical grant and derived one do not match: %w", err)
	}
	g.CanonicalGrant = canonical

	return nil
}

// TableName returns the tablename to override the default gorm table name
func (g *RoleGrant) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultRoleGrantTable
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (g *RoleGrant) SetTableName(n string) {
	g.tableName = n
}
