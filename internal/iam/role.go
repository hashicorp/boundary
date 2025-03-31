// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const (
	defaultRoleTableName        = "iam_role"
	defaultGlobalRoleTableName  = "iam_role_global"
	defaultOrgRoleTableName     = "iam_role_org"
	defaultProjectRoleTableName = "iam_role_project"
)

// Roles are granted permissions and assignable to Users and Groups.
type Role struct {
	PublicId    string
	ScopeId     string
	Name        string
	Description string
	CreateTime  *timestamp.Timestamp
	UpdateTime  *timestamp.Timestamp
	Version     uint32
	GrantScopes []*RoleGrantScope `gorm:"-"`
}

func (role *Role) GetPublicId() string {
	if role == nil {
		return ""
	}
	return role.PublicId
}

func (role *Role) GetScopeId() string {
	if role == nil {
		return ""
	}
	return role.ScopeId
}
func (role *Role) GetName() string {
	if role == nil {
		return ""
	}
	return role.Name
}

func (role *Role) GetDescription() string {
	if role == nil {
		return ""
	}
	return role.Description
}

func (role *Role) GetCreateTime() *timestamp.Timestamp {
	if role == nil {
		return nil
	}
	return role.CreateTime
}

func (role *Role) GetUpdateTime() *timestamp.Timestamp {
	if role == nil {
		return nil
	}
	return role.UpdateTime
}

func (role *Role) GetVersion() uint32 {
	if role == nil {
		return 0
	}
	return role.Version
}

// ensure that Role implements the interfaces of: Resource, Cloneable, and db.VetForWriter.
var (
	_ Resource                = (*globalRole)(nil)
	_ Cloneable               = (*globalRole)(nil)
	_ db.VetForWriter         = (*globalRole)(nil)
	_ oplog.ReplayableMessage = (*globalRole)(nil)

	_ Resource                = (*orgRole)(nil)
	_ Cloneable               = (*orgRole)(nil)
	_ db.VetForWriter         = (*orgRole)(nil)
	_ oplog.ReplayableMessage = (*orgRole)(nil)

	_ Resource                = (*projectRole)(nil)
	_ Cloneable               = (*projectRole)(nil)
	_ db.VetForWriter         = (*projectRole)(nil)
	_ oplog.ReplayableMessage = (*projectRole)(nil)
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
		ScopeId:     scopeId,
		Name:        opts.withName,
		Description: opts.withDescription,
	}
	return r, nil
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

func (role *Role) getResourceType() resource.Type {
	return resource.Role
}

// GetScope returns the scope for the Role.
func (role *Role) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, role)
}

// GetResourceType returns the type of the Role.
func (*Role) GetResourceType() resource.Type { return resource.Role }

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

type deletedRole struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedRole) TableName() string {
	return "iam_role_deleted"
}

// globalRole is a type embedding store.GlobalRole used to interact with iam_role_global table which contains
// all iam_role entries that are created in global-level scopes through gorm.
type globalRole struct {
	*store.GlobalRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
}

func (g *globalRole) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return defaultGlobalRoleTableName
}

func (g *globalRole) SetTableName(n string) {
	g.tableName = n
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

func allocGlobalRole() globalRole {
	return globalRole{
		GlobalRole: &store.GlobalRole{},
	}
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
func (g *globalRole) toRole() *Role {
	if g == nil {
		return nil
	}
	ret := &Role{
		PublicId:    g.GetPublicId(),
		ScopeId:     g.GetScopeId(),
		Name:        g.GetName(),
		Description: g.GetDescription(),
		CreateTime:  g.GetCreateTime(),
		UpdateTime:  g.GetUpdateTime(),
		Version:     g.GetVersion(),
	}
	for _, grantScope := range g.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

// orgRole is a type embedding store.OrgRole used to interact with iam_role_org table which contains
// all iam_role entries that are created in org-level scopes through gorm.
type orgRole struct {
	*store.OrgRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
}

func (o *orgRole) TableName() string {
	if o.tableName != "" {
		return o.tableName
	}
	return defaultOrgRoleTableName
}

func (o *orgRole) SetTableName(n string) {
	o.tableName = n
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

func allocOrgRole() orgRole {
	return orgRole{
		OrgRole: &store.OrgRole{},
	}
}

func (o *orgRole) Clone() any {
	cp := proto.Clone(o.OrgRole)
	ret := &orgRole{
		OrgRole: cp.(*store.OrgRole),
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
func (o *orgRole) toRole() *Role {
	if o == nil {
		return nil
	}
	ret := &Role{
		PublicId:    o.GetPublicId(),
		ScopeId:     o.GetScopeId(),
		Name:        o.GetName(),
		Description: o.GetDescription(),
		CreateTime:  o.GetCreateTime(),
		UpdateTime:  o.GetUpdateTime(),
		Version:     o.GetVersion(),
	}
	for _, grantScope := range o.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

// projectRole is a type embedding store.ProjectRole used to interact with iam_role_project table which contains
// all iam_role entries that are created in project-level scopes through gorm.
type projectRole struct {
	*store.ProjectRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
}

func (p *projectRole) TableName() string {
	if p.tableName != "" {
		return p.tableName
	}
	return defaultProjectRoleTableName
}

func (p *projectRole) SetTableName(n string) {
	p.tableName = n
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

func allocProjectRole() projectRole {
	return projectRole{
		ProjectRole: &store.ProjectRole{},
	}
}

func (p *projectRole) Clone() any {
	cp := proto.Clone(p.ProjectRole)
	ret := &projectRole{
		ProjectRole: cp.(*store.ProjectRole),
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
func (p *projectRole) toRole() *Role {
	if p == nil {
		return nil
	}
	ret := &Role{
		PublicId:    p.GetPublicId(),
		ScopeId:     p.GetScopeId(),
		Name:        p.GetName(),
		Description: p.GetDescription(),
		CreateTime:  p.GetCreateTime(),
		UpdateTime:  p.GetUpdateTime(),
		Version:     p.GetVersion(),
	}
	for _, grantScope := range p.GrantScopes {
		ret.GrantScopes = append(ret.GrantScopes, grantScope.Clone().(*RoleGrantScope))
	}
	return ret
}

// getRoleScopeId returns scopeID for the Role from the base type iam_role table
// use this to get scope ID to determine which of the role subtype tables to operate on
func getRoleScopeId(ctx context.Context, r db.Reader, roleId string) (string, error) {
	const (
		op    = "iam.getRoleScopeId"
		query = `select scope_id from iam_role where public_id = $1`
	)
	if roleId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing role ID")
	}
	if r == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	}
	rows, err := r.Query(ctx, query, []any{roleId})
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("failed to lookup role scope ID"))
	}
	var scopeId string
	cnt := 0
	for rows.Next() {
		cnt++
		if err := r.ScanRows(ctx, rows, &scopeId); err != nil {
			return "", errors.Wrap(ctx, err, op, errors.WithMsg("failed scan results from querying role scope ID"))
		}
	}
	if err := rows.Err(); err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("unexpected error scanning results from querying role scope ID"))
	}
	if cnt == 0 {
		return "", errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("role %s not found", roleId))
	}
	return scopeId, nil
}
