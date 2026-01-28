// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"
	"strings"

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
	defaultOrgRoleIndividualGrantScopeTable           = "iam_role_org_individual_grant_scope"
)

// ensure that RoleGrantScope implements the interfaces of: Cloneable and db.VetForWriter
var (
	_ Cloneable       = (*RoleGrantScope)(nil)
	_ db.VetForWriter = (*RoleGrantScope)(nil)

	_ Cloneable               = (*globalRoleIndividualOrgGrantScope)(nil)
	_ db.VetForWriter         = (*globalRoleIndividualOrgGrantScope)(nil)
	_ oplog.ReplayableMessage = (*globalRoleIndividualOrgGrantScope)(nil)
	_ roleGrantScoper         = (*globalRoleIndividualOrgGrantScope)(nil)

	_ Cloneable               = (*globalRoleIndividualProjectGrantScope)(nil)
	_ db.VetForWriter         = (*globalRoleIndividualProjectGrantScope)(nil)
	_ oplog.ReplayableMessage = (*globalRoleIndividualProjectGrantScope)(nil)
	_ roleGrantScoper         = (*globalRoleIndividualProjectGrantScope)(nil)

	_ Cloneable               = (*orgRoleIndividualGrantScope)(nil)
	_ db.VetForWriter         = (*orgRoleIndividualGrantScope)(nil)
	_ oplog.ReplayableMessage = (*orgRoleIndividualGrantScope)(nil)
	_ roleGrantScoper         = (*orgRoleIndividualGrantScope)(nil)
)

// roleGrantScoper is an interface for converting internal grantScopeTypes to exported RoleGrantScope
type roleGrantScoper interface {
	roleGrantScope() *RoleGrantScope
}

// RoleGrantScope defines the grant scopes that are assigned to a role
type RoleGrantScope struct {
	CreateTime       *timestamp.Timestamp
	RoleId           string
	ScopeIdOrSpecial string
}

func (r *RoleGrantScope) GetCreateTime() *timestamp.Timestamp {
	if r == nil {
		return nil
	}
	return r.CreateTime
}

func (r *RoleGrantScope) GetRoleId() string {
	if r == nil {
		return ""
	}
	return r.RoleId
}

func (r *RoleGrantScope) GetScopeIdOrSpecial() string {
	if r == nil {
		return ""
	}
	return r.ScopeIdOrSpecial
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

// globalRoleIndividualOrgGrantScope defines the grant org scopes
// that are assigned to a global role
type globalRoleIndividualOrgGrantScope struct {
	*store.GlobalRoleIndividualOrgGrantScope
	tableName string `gorm:"-"`
}

func (g *globalRoleIndividualOrgGrantScope) roleGrantScope() *RoleGrantScope {
	if g == nil {
		return nil
	}
	return &RoleGrantScope{
		CreateTime:       g.CreateTime,
		RoleId:           g.RoleId,
		ScopeIdOrSpecial: g.GetScopeId(),
	}
}

func (g *globalRoleIndividualOrgGrantScope) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultGlobalRoleIndividualOrgGrantScopeTable
}

func (g *globalRoleIndividualOrgGrantScope) SetTableName(name string) {
	g.tableName = name
}

func (g *globalRoleIndividualOrgGrantScope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(GlobalRoleIndividualOrgGrantScope).VetForWrite"
	if g.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if g.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if globals.ResourceInfoFromPrefix(g.ScopeId).Type != resource.Scope &&
		strings.HasPrefix(g.String(), globals.OrgPrefix) {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid scope ID %s", g.ScopeId))
	}
	return nil
}

func (g *globalRoleIndividualOrgGrantScope) Clone() any {
	cp := proto.Clone(g.GlobalRoleIndividualOrgGrantScope)
	return &globalRoleIndividualOrgGrantScope{
		GlobalRoleIndividualOrgGrantScope: cp.(*store.GlobalRoleIndividualOrgGrantScope),
	}
}

// globalRoleIndividualProjectGrantScope defines the grant project scopes
// that are assigned to a global role
type globalRoleIndividualProjectGrantScope struct {
	*store.GlobalRoleIndividualProjectGrantScope
	tableName string `gorm:"-"`
}

func (g *globalRoleIndividualProjectGrantScope) roleGrantScope() *RoleGrantScope {
	if g == nil {
		return nil
	}
	return &RoleGrantScope{
		CreateTime:       g.GetCreateTime(),
		RoleId:           g.GetRoleId(),
		ScopeIdOrSpecial: g.GetScopeId(),
	}
}

func (g *globalRoleIndividualProjectGrantScope) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultGlobalRoleIndividualProjectGrantScopeTable
}

func (g *globalRoleIndividualProjectGrantScope) SetTableName(name string) {
	g.tableName = name
}

func (g *globalRoleIndividualProjectGrantScope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(GlobalRoleIndividualProjectGrantScope).VetForWrite"
	if g.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if g.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if globals.ResourceInfoFromPrefix(g.ScopeId).Type != resource.Scope &&
		strings.HasPrefix(g.String(), globals.ProjectPrefix) {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid scope ID %s", g.ScopeId))
	}
	return nil
}

func (g *globalRoleIndividualProjectGrantScope) Clone() any {
	cp := proto.Clone(g.GlobalRoleIndividualProjectGrantScope)
	return &globalRoleIndividualProjectGrantScope{
		GlobalRoleIndividualProjectGrantScope: cp.(*store.GlobalRoleIndividualProjectGrantScope),
	}
}

// OrgRoleIndividualGrantScope defines the grant project scopes
// that are assigned to an org role
type orgRoleIndividualGrantScope struct {
	*store.OrgRoleIndividualGrantScope
	tableName string `gorm:"-"`
}

func (g *orgRoleIndividualGrantScope) roleGrantScope() *RoleGrantScope {
	if g == nil {
		return nil
	}
	return &RoleGrantScope{
		CreateTime:       g.GetCreateTime(),
		RoleId:           g.GetRoleId(),
		ScopeIdOrSpecial: g.GetScopeId(),
	}
}

func (g *orgRoleIndividualGrantScope) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultOrgRoleIndividualGrantScopeTable
}

func (g *orgRoleIndividualGrantScope) SetTableName(name string) {
	g.tableName = name
}

func (g *orgRoleIndividualGrantScope) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(OrgRoleIndividualGrantScope).VetForWrite"
	if g.RoleId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if g.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if globals.ResourceInfoFromPrefix(g.ScopeId).Type != resource.Scope &&
		strings.HasPrefix(g.String(), globals.ProjectPrefix) {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid scope ID %s", g.ScopeId))
	}
	return nil
}

func (g *orgRoleIndividualGrantScope) Clone() any {
	cp := proto.Clone(g.OrgRoleIndividualGrantScope)
	return &orgRoleIndividualGrantScope{
		OrgRoleIndividualGrantScope: cp.(*store.OrgRoleIndividualGrantScope),
	}
}
