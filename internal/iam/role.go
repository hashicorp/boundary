// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/oplog"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

const (
	defaultRoleTableName        = "iam_role"
	defaultGlobalRoleTableName  = "iam_global_role"
	defaultOrgRoleTableName     = "iam_org_role"
	defaultProjectRoleTableName = "iam_project_role"
)

// Role is a set of granted permissions and assignable to Users and Groups.
type Role struct {
	*store.Role
	PublicId    string
	ScopeId     string
	Name        string
	Description string
	CreateTime  *timestamp.Timestamp
	UpdateTime  *timestamp.Timestamp
	Version     uint32
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
}

type globalRole struct {
	*store.GlobalRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
}

func (g *globalRole) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultRoleTableName
}

func (g *globalRole) SetTableName(n string) {
	g.tableName = n
}

// newGlobalRole creates a new in memory role in the global scope
// allowed options include: WithDescription, WithName.
func newGlobalRole(ctx context.Context, opt ...Option) (*globalRole, error) {
	const op = "iam.newGlobalRole"
	opts := getOpts(opt...)
	r := &globalRole{
		GlobalRole: &store.GlobalRole{
			ScopeId:     globals.GlobalPrefix,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return r, nil
}

func (g *globalRole) toRole() *Role {
	ret := &Role{
		PublicId:    g.PublicId,
		ScopeId:     g.ScopeId,
		Name:        g.Name,
		Description: g.Description,
		CreateTime:  g.CreateTime,
		UpdateTime:  g.UpdateTime,
		Version:     g.Version,
	}
	for _, grantScope := range g.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

func (g *globalRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(globalRole).VetForWrite"
	if g.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, g, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (g *globalRole) Clone() any {
	cp := proto.Clone(g.GlobalRole)
	ret := &globalRole{
		GlobalRole: cp.(*store.GlobalRole),
	}
	for _, grantScope := range g.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}
func (g *globalRole) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, g)
}
func (g *globalRole) GetResourceType() resource.Type { return resource.Role }
func (g *globalRole) getResourceType() resource.Type { return resource.Role }
func (g *globalRole) Actions() map[string]action.Type {
	ret := CrudlActions()
	ret[action.AddGrants.String()] = action.AddGrants
	ret[action.RemoveGrants.String()] = action.RemoveGrants
	ret[action.SetGrants.String()] = action.SetGrants
	ret[action.AddPrincipals.String()] = action.AddPrincipals
	ret[action.RemovePrincipals.String()] = action.RemovePrincipals
	ret[action.SetPrincipals.String()] = action.SetPrincipals
	return ret
}
func allocGlobalRole() globalRole {
	return globalRole{
		GlobalRole: &store.GlobalRole{},
	}
}

type orgRole struct {
	*store.OrgRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
}

func (o *orgRole) TableName() string {
	if o.tableName != "" {
		return o.tableName
	}
	return defaultRoleTableName
}

func (o *orgRole) SetTableName(n string) {
	o.tableName = n
}

// newOrgRole creates a new in memory role in a org scope
// allowed options include: WithDescription, WithName.
func newOrgRole(ctx context.Context, orgId string, opt ...Option) (*orgRole, error) {
	const op = "iam.newOrgRole"
	if orgId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if !strings.HasPrefix(orgId, globals.OrgPrefix) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scope must be an org")
	}
	opts := getOpts(opt...)
	r := &orgRole{
		OrgRole: &store.OrgRole{
			ScopeId:     orgId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return r, nil
}
func (o *orgRole) toRole() *Role {
	ret := &Role{
		PublicId:    o.PublicId,
		ScopeId:     o.ScopeId,
		Name:        o.Name,
		Description: o.Description,
		CreateTime:  o.CreateTime,
		UpdateTime:  o.UpdateTime,
		Version:     o.Version,
	}
	for _, grantScope := range o.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

func (o *orgRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(orgRole).VetForWrite"
	if o.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, o, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (o *orgRole) Clone() any {
	cp := proto.Clone(o.OrgRole)
	ret := &globalRole{
		GlobalRole: cp.(*store.GlobalRole),
	}
	for _, grantScope := range o.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}
func (o *orgRole) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, o)
}
func (o *orgRole) GetResourceType() resource.Type { return resource.Role }
func (o *orgRole) getResourceType() resource.Type { return resource.Role }
func (o *orgRole) Actions() map[string]action.Type {
	ret := CrudlActions()
	ret[action.AddGrants.String()] = action.AddGrants
	ret[action.RemoveGrants.String()] = action.RemoveGrants
	ret[action.SetGrants.String()] = action.SetGrants
	ret[action.AddPrincipals.String()] = action.AddPrincipals
	ret[action.RemovePrincipals.String()] = action.RemovePrincipals
	ret[action.SetPrincipals.String()] = action.SetPrincipals
	return ret
}
func allocOrgRole() orgRole {
	return orgRole{
		OrgRole: &store.OrgRole{},
	}
}

type projectRole struct {
	*store.ProjectRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
}

func (p *projectRole) TableName() string {
	if p.tableName != "" {
		return p.tableName
	}
	return defaultRoleTableName
}

func (p *projectRole) SetTableName(n string) {
	p.tableName = n
}

// newProjectRole creates a new in memory role in a project scope
// allowed options include: WithDescription, WithName.
func newProjectRole(ctx context.Context, projectId string, opt ...Option) (*projectRole, error) {
	const op = "iam.newProjectRole"
	if projectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if !strings.HasPrefix(projectId, globals.ProjectPrefix) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scope must be a project")
	}
	opts := getOpts(opt...)
	r := &projectRole{
		ProjectRole: &store.ProjectRole{
			ScopeId:     projectId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return r, nil
}

func (p *projectRole) toRole() *Role {
	ret := &Role{
		PublicId:    p.PublicId,
		ScopeId:     p.ScopeId,
		Name:        p.Name,
		Description: p.Description,
		CreateTime:  p.CreateTime,
		UpdateTime:  p.UpdateTime,
		Version:     p.Version,
	}
	for _, grantScope := range p.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

func (p *projectRole) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(projectRole).VetForWrite"
	if p.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, p, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (p *projectRole) Clone() any {
	cp := proto.Clone(p.ProjectRole)
	ret := &globalRole{
		GlobalRole: cp.(*store.GlobalRole),
	}
	for _, grantScope := range p.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

func (p *projectRole) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, p)
}
func (p *projectRole) GetResourceType() resource.Type { return resource.Role }
func (p *projectRole) getResourceType() resource.Type { return resource.Role }
func (p *projectRole) Actions() map[string]action.Type {
	ret := CrudlActions()
	ret[action.AddGrants.String()] = action.AddGrants
	ret[action.RemoveGrants.String()] = action.RemoveGrants
	ret[action.SetGrants.String()] = action.SetGrants
	ret[action.AddPrincipals.String()] = action.AddPrincipals
	ret[action.RemovePrincipals.String()] = action.RemovePrincipals
	ret[action.SetPrincipals.String()] = action.SetPrincipals
	return ret
}
func allocProjectRole() projectRole {
	return projectRole{
		ProjectRole: &store.ProjectRole{},
	}
}

// ensure that Role implements the interfaces of: Resource, Cloneable, and db.VetForWriter.
var (
	_ Resource                = (*globalRole)(nil)
	_ Cloneable               = (*globalRole)(nil)
	_ oplog.ReplayableMessage = (*globalRole)(nil)
	_ db.VetForWriter         = (*globalRole)(nil)

	_ Resource                = (*orgRole)(nil)
	_ Cloneable               = (*orgRole)(nil)
	_ oplog.ReplayableMessage = (*orgRole)(nil)
	_ db.VetForWriter         = (*orgRole)(nil)

	_ Resource                = (*projectRole)(nil)
	_ Cloneable               = (*projectRole)(nil)
	_ oplog.ReplayableMessage = (*projectRole)(nil)
	_ db.VetForWriter         = (*projectRole)(nil)

	_ Resource        = (*Role)(nil)
	_ Cloneable       = (*Role)(nil)
	_ db.VetForWriter = (*Role)(nil)
)

// NewRole creates a new in memory role with a scope (project/org)
// allowed options include: withDescription, WithName.
func NewRole(ctx context.Context, scopeId string, opt ...Option) (*Role, error) {
	const op = "iam.NewRole"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)
	r := &Role{
		Role: &store.Role{
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return r, nil
}

// Clone creates a clone of the Role.
func (role *Role) Clone() any {
	cp := proto.Clone(role.Role)
	ret := &Role{
		Role: cp.(*store.Role),
	}
	for _, grantScope := range role.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

// VetForWrite implements db.VetForWrite() interface.
func (role *Role) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "iam.(Role).VetForWrite"
	if role.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if err := validateScopeForWrite(ctx, r, role, opType, opt...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (role *Role) validScopeTypes() []scope.Type {
	return []scope.Type{scope.Global, scope.Org, scope.Project}
}

// GetScope returns the scope for the Role.
func (role *Role) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, role)
}

// GetResourceType returns the type of the Role.
func (*Role) GetResourceType() resource.Type { return resource.Role }
func (*Role) getResourceType() resource.Type { return resource.Role }

// Actions returns the available actions for Role.
func (*Role) Actions() map[string]action.Type {
	ret := CrudlActions()
	ret[action.AddGrants.String()] = action.AddGrants
	ret[action.RemoveGrants.String()] = action.RemoveGrants
	ret[action.SetGrants.String()] = action.SetGrants
	ret[action.AddPrincipals.String()] = action.AddPrincipals
	ret[action.RemovePrincipals.String()] = action.RemovePrincipals
	ret[action.SetPrincipals.String()] = action.SetPrincipals
	return ret
}

// TableName returns the tablename to override the default gorm table name.
func (role *Role) TableName() string {
	if role.tableName != "" {
		return role.tableName
	}
	return defaultRoleTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (role *Role) SetTableName(n string) {
	role.tableName = n
}

func allocRole() Role {
	return Role{
		Role: &store.Role{},
	}
}

type deletedRole struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedRole) TableName() string {
	return "iam_role_deleted"
}
