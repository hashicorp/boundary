// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const defaultRoleGrantScopeTable = "iam_role_grant_scope"

// RoleGrantScope defines the grant scopes that are assigned to a role
type RoleGrantScope struct {
	*store.RoleGrantScope
	tableName string `gorm:"-"`
}

// ensure that RoleGrantScope implements the interfaces of: Cloneable and db.VetForWriter
var (
	_ Cloneable       = (*RoleGrantScope)(nil)
	_ db.VetForWriter = (*RoleGrantScope)(nil)
)

// NewRoleGrantScope creates a new in memory role grant scope
func NewRoleGrantScope(ctx context.Context, roleId string, grantScope string, _ ...Option) (*RoleGrantScope, error) {
	const op = "iam.NewRoleGrantScope"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if grantScope == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grant scope")
	}

	switch {
	case grantScope == "global",
		grantScope == "this",
		grantScope == "children",
		grantScope == "descendants":
	case globals.ResourceInfoFromPrefix(grantScope).Type == resource.Scope:
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown grant scope id %q", grantScope))
	}
	rgs := &RoleGrantScope{
		RoleGrantScope: &store.RoleGrantScope{
			RoleId:  roleId,
			ScopeId: grantScope,
		},
	}
	return rgs, nil
}

func allocRoleGrantScope() RoleGrantScope {
	return RoleGrantScope{
		RoleGrantScope: &store.RoleGrantScope{},
	}
}

// Clone creates a clone of the RoleGrantScope
func (g *RoleGrantScope) Clone() any {
	cp := proto.Clone(g.RoleGrantScope)
	return &RoleGrantScope{
		RoleGrantScope: cp.(*store.RoleGrantScope),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (g *RoleGrantScope) VetForWrite(ctx context.Context, _ db.Reader, _ db.OpType, _ ...db.Option) error {
	const op = "iam.(RoleGrantScope).VetForWrite"
	if g.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if g.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	switch {
	case g.ScopeId == "global",
		g.ScopeId == "this",
		g.ScopeId == "children":
	case globals.ResourceInfoFromPrefix(g.ScopeId).Type == resource.Scope:
	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown grant scope id %q", g.ScopeId))
	}

	return nil
}

// TableName returns the tablename to override the default gorm table name
func (g *RoleGrantScope) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultRoleGrantScopeTable
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (g *RoleGrantScope) SetTableName(n string) {
	g.tableName = n
}
