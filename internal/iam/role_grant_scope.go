// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

const (
	defaultRoleGrantScopeTable                        = "iam_role_grant_scope"
	defaultGlobalRoleIndividualOrgGrantScopeTable     = "iam_role_global_individual_org_grant_scope"
	defaultGlobalRoleIndividualProjectGrantScopeTable = "iam_role_global_individual_project_grant_scope"
)

// ensure that RoleGrantScope implements the interfaces of: Cloneable and db.VetForWriter
var (
	_ Cloneable       = (*RoleGrantScope)(nil)
	_ db.VetForWriter = (*RoleGrantScope)(nil)

	_ Cloneable               = (*GlobalRoleIndividualOrgGrantScope)(nil)
	_ db.VetForWriter         = (*GlobalRoleIndividualOrgGrantScope)(nil)
	_ oplog.ReplayableMessage = (*GlobalRoleIndividualOrgGrantScope)(nil)

	_ Cloneable               = (*GlobalRoleIndividualProjectGrantScope)(nil)
	_ db.VetForWriter         = (*GlobalRoleIndividualProjectGrantScope)(nil)
	_ oplog.ReplayableMessage = (*GlobalRoleIndividualProjectGrantScope)(nil)
)

// RoleGrantScope defines the grant scopes that are assigned to a role
type RoleGrantScope struct {
	CreateTime       *timestamp.Timestamp
	RoleId           string
	ScopeIdOrSpecial string
}

// NewRoleGrantScope creates a new in memory role grant scope. No options are
// supported.
func NewRoleGrantScope(ctx context.Context, roleId string, grantScope string, _ ...Option) (*RoleGrantScope, error) {
	const op = "iam.NewRoleGrantScope"

	switch {
	case roleId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	case grantScope == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grant scope")
	case grantScope == scope.Global.String(),
		grantScope == globals.GrantScopeThis,
		grantScope == globals.GrantScopeChildren,
		grantScope == globals.GrantScopeDescendants:
	case globals.ResourceInfoFromPrefix(grantScope).Type == resource.Scope:
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown grant scope id %q", grantScope))
	}

	rgs := &RoleGrantScope{
		RoleId:           roleId,
		ScopeIdOrSpecial: grantScope,
	}

	return rgs, nil
}

// Clone creates a clone of the RoleGrantScope
func (g *RoleGrantScope) Clone() any {
	return &RoleGrantScope{
		CreateTime:       g.CreateTime,
		RoleId:           g.RoleId,
		ScopeIdOrSpecial: g.ScopeIdOrSpecial,
	}
}

// VetForWrite implements db.VetForWrite() interface
func (g *RoleGrantScope) VetForWrite(ctx context.Context, _ db.Reader, _ db.OpType, _ ...db.Option) error {
	const op = "iam.(RoleGrantScope).VetForWrite"
	if g.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if g.ScopeIdOrSpecial == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	switch {
	case g.ScopeIdOrSpecial == scope.Global.String(),
		g.ScopeIdOrSpecial == globals.GrantScopeThis,
		g.ScopeIdOrSpecial == globals.GrantScopeChildren,
		g.ScopeIdOrSpecial == globals.GrantScopeDescendants:
	case globals.ResourceInfoFromPrefix(g.ScopeIdOrSpecial).Type == resource.Scope:
	default:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown grant scope id %q", g.ScopeIdOrSpecial))
	}

	return nil
}

// GlobalRoleIndividualOrgGrantScope defines the grant org scopes
// that are assigned to a global role
type GlobalRoleIndividualOrgGrantScope struct {
	*store.GlobalRoleIndividualOrgGrantScope
	tableName string `gorm:"-"`
}

func (g *GlobalRoleIndividualOrgGrantScope) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultGlobalRoleIndividualOrgGrantScopeTable
}

func (g *GlobalRoleIndividualOrgGrantScope) SetTableName(name string) {
	g.tableName = name
}

func (g *GlobalRoleIndividualOrgGrantScope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(GlobalRoleIndividualOrgGrantScope).VetForWrite"
	if g.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if g.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if globals.ResourceInfoFromPrefix(g.ScopeId).Type != resource.Scope {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid scope ID %s", g.ScopeId))
	}
	return nil
}

func (g *GlobalRoleIndividualOrgGrantScope) Clone() any {
	cp := proto.Clone(g.GlobalRoleIndividualOrgGrantScope)
	return &GlobalRoleIndividualOrgGrantScope{
		GlobalRoleIndividualOrgGrantScope: cp.(*store.GlobalRoleIndividualOrgGrantScope),
	}
}

// GlobalRoleIndividualProjectGrantScope defines the grant project scopes
// that are assigned to a global role
type GlobalRoleIndividualProjectGrantScope struct {
	*store.GlobalRoleIndividualProjectGrantScope
	tableName string `gorm:"-"`
}

func (g *GlobalRoleIndividualProjectGrantScope) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultGlobalRoleIndividualProjectGrantScopeTable
}

func (g *GlobalRoleIndividualProjectGrantScope) SetTableName(name string) {
	g.tableName = name
}

func (g *GlobalRoleIndividualProjectGrantScope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(GlobalRoleIndividualProjectGrantScope).VetForWrite"
	if g.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if g.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if globals.ResourceInfoFromPrefix(g.ScopeId).Type != resource.Scope {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid scope ID %s", g.ScopeId))
	}
	return nil
}

func (g *GlobalRoleIndividualProjectGrantScope) Clone() any {
	cp := proto.Clone(g.GlobalRoleIndividualProjectGrantScope)
	return &GlobalRoleIndividualProjectGrantScope{
		GlobalRoleIndividualProjectGrantScope: cp.(*store.GlobalRoleIndividualProjectGrantScope),
	}
}
