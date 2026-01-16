// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
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
var (
	_ Cloneable       = (*RoleGrant)(nil)
	_ db.VetForWriter = (*RoleGrant)(nil)
)

// NewRoleGrant creates a new in memory role grant
func NewRoleGrant(ctx context.Context, roleId string, grant string, _ ...Option) (*RoleGrant, error) {
	const op = "iam.NewRoleGrant"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if grant == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grant")
	}

	// Validate that the grant parses successfully. Note that we fake the scope
	// here to avoid a lookup as the scope is only relevant at actual ACL
	// checking time and we just care that it parses correctly.
	perm, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: "o_abcd1234", GrantScopeId: "o_abcd1234", Grant: grant})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("parsing grant string"))
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
func (g *RoleGrant) Clone() any {
	cp := proto.Clone(g.RoleGrant)
	return &RoleGrant{
		RoleGrant: cp.(*store.RoleGrant),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (g *RoleGrant) VetForWrite(ctx context.Context, _ db.Reader, _ db.OpType, _ ...db.Option) error {
	const op = "iam.(RoleGrant).VetForWrite"
	if g.RawGrant == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing grant")
	}

	// Validate that the grant parses successfully. Note that we fake the scope
	// here to avoid a lookup as the scope is only relevant at actual ACL
	// checking time and we just care that it parses correctly. We may have
	// already done this in NewRoleGrant, but we re-check and set it here
	// anyways because it should still be part of the vetting process.
	perm, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: "o_abcd1234", GrantScopeId: "o_abcd1234", Grant: g.RawGrant})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("parsing grant string"))
	}
	canonical := perm.CanonicalString()
	if g.CanonicalGrant != "" && g.CanonicalGrant != canonical {
		return errors.Wrap(ctx, err, op, errors.WithMsg("existing canonical grant and derived one do not match"))
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
