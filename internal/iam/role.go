// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/globals"
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
	defaultGlobalRoleTableName  = "iam_role_global"
	defaultOrgRoleTableName     = "iam_role_org"
	defaultProjectRoleTableName = "iam_role_project"
)

// roleGrantScopeUpdater represents an internal scope type specific role structs that
// support grant scope columns. Currently this only applies to globalRole and orgRole
// this is used in SetRoleGrantScope, AddRoleGrantScope, DeleteRoleGrantScope
type roleGrantScopeUpdater interface {
	// setVersion sets value of `Version` of this role. This is used in
	// `repository_grant_scope` operations where version column of the associated role
	// has to increase when grant scopes list is changed (add/remove) which is done in a different table.
	// This version bump cannot be done by automatically with trigger and is being handled in the application code
	setVersion(version uint32)

	// setThisGrantScope sets value of `GrantThisRoleScope` of this role which control
	// whether this role has 'this' scope granted to it
	setGrantThisRoleScope(grantThis bool)

	// setGrantScope sets value of `GrantScope` column of this role. The allowed values depends on the scope
	// that the role is in
	// 	- global-role: ['descendants', 'children']
	// 	- org-role: ['children']
	//	- project-role: [] (None)
	// This value controls whether hierarchical grant scope is granted to this role
	// This method may return error when role does not support hierarchical grant scope (project role)
	setGrantScope(ctx context.Context, specialGrant string) error

	// removeHierarchicalGrantScope removes all hierarchical grant scopes from a role ['children', 'descendants']
	// and sets 'grant_scope' column to 'individual' if required
	// 	- global-role: may remove ['descendants', 'children']
	// 	- org-role: may remove ['children']
	//	- project-role: no-op as hierarchical grant scope isn't supported for project roles
	removeGrantScope()

	// GrantThisRoleScope return value of `GrantScopeThis` column as *RoleGrantScope.
	// Prior to the grants refactor, `this` grant scope is granted to a role by
	// inserting a row to 'role_grant_scope' table, but we've moved on to storing
	// 'this' grant as a dedicated column in the type-specific role tables
	grantThisRoleScope() (*RoleGrantScope, bool)

	// grantScope returns hierarchical grant scopes ['descendants', 'children'] if available.
	// returns nil, false if grant_scope is 'individual'
	grantScope() (*RoleGrantScope, bool)
}

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
	_ roleGrantScopeUpdater   = (*globalRole)(nil)
	_ Resource                = (*globalRole)(nil)
	_ Cloneable               = (*globalRole)(nil)
	_ db.VetForWriter         = (*globalRole)(nil)
	_ oplog.ReplayableMessage = (*globalRole)(nil)

	_ roleGrantScopeUpdater   = (*orgRole)(nil)
	_ Resource                = (*orgRole)(nil)
	_ Cloneable               = (*orgRole)(nil)
	_ db.VetForWriter         = (*orgRole)(nil)
	_ oplog.ReplayableMessage = (*orgRole)(nil)

	_ roleGrantScopeUpdater   = (*projectRole)(nil)
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

func (g *globalRole) removeGrantScope() {
	if g != nil {
		g.GrantScope = globals.GrantScopeIndividual
	}
}

func (g *globalRole) setVersion(version uint32) {
	if g == nil {
		return
	}
	g.Version = version
}

func (g *globalRole) setGrantThisRoleScope(grantThis bool) {
	if g == nil {
		return
	}
	g.GrantThisRoleScope = grantThis
}

func (g *globalRole) setGrantScope(ctx context.Context, specialGrant string) error {
	if g != nil {
		g.GrantScope = specialGrant
	}
	return nil
}

func (g *globalRole) grantThisRoleScope() (*RoleGrantScope, bool) {
	if g == nil {
		return &RoleGrantScope{}, false
	}
	if !g.GrantThisRoleScope {
		return &RoleGrantScope{}, false
	}
	return &RoleGrantScope{
		CreateTime:       g.GrantThisRoleScopeUpdateTime,
		RoleId:           g.PublicId,
		ScopeIdOrSpecial: globals.GrantScopeThis,
	}, true
}

func (g *globalRole) grantScope() (*RoleGrantScope, bool) {
	if g == nil {
		return nil, false
	}
	if g.GrantScope == globals.GrantScopeIndividual {
		return nil, false
	}
	return &RoleGrantScope{
		CreateTime:       g.GrantScopeUpdateTime,
		RoleId:           g.PublicId,
		ScopeIdOrSpecial: g.GrantScope,
	}, true
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

func (o *orgRole) removeGrantScope() {
	if o != nil {
		o.GrantScope = globals.GrantScopeIndividual
	}
}

func (o *orgRole) setVersion(version uint32) {
	if o == nil {
		return
	}
	o.Version = version
}

func (o *orgRole) setGrantThisRoleScope(grantThis bool) {
	if o == nil {
		return
	}
	o.GrantThisRoleScope = grantThis
}

func (o *orgRole) setGrantScope(ctx context.Context, specialGrant string) error {
	if o != nil {
		o.GrantScope = specialGrant
	}
	return nil
}

func (o *orgRole) grantThisRoleScope() (*RoleGrantScope, bool) {
	if o == nil {
		return &RoleGrantScope{}, false
	}
	if !o.GrantThisRoleScope {
		return &RoleGrantScope{}, false
	}
	return &RoleGrantScope{
		CreateTime:       o.GrantThisRoleScopeUpdateTime,
		RoleId:           o.PublicId,
		ScopeIdOrSpecial: globals.GrantScopeThis,
	}, true
}

func (o *orgRole) grantScope() (*RoleGrantScope, bool) {
	if o == nil {
		return nil, false
	}
	if o.GrantScope == globals.GrantScopeIndividual {
		return nil, false
	}
	return &RoleGrantScope{
		CreateTime:       o.GrantScopeUpdateTime,
		RoleId:           o.PublicId,
		ScopeIdOrSpecial: o.GrantScope,
	}, true
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

func (p *projectRole) removeGrantScope() {
	// no-op since hierarchical isn't supported by project roles
	return
}

func (p *projectRole) setGrantScope(ctx context.Context, specialGrant string) error {
	const op = "iam.(projectRole).setGrantScope"
	return errors.New(ctx, errors.InvalidParameter, op, "hierarchical grant scope is not allowed for project role")
}

func (p *projectRole) grantScope() (*RoleGrantScope, bool) {
	return &RoleGrantScope{}, false
}

func (p *projectRole) setVersion(version uint32) {
	if p == nil {
		return
	}
	p.Version = version
}

func (p *projectRole) setGrantThisRoleScope(grantThis bool) {
	if p == nil {
		return
	}
	p.GrantThisRoleScope = grantThis
}

func (p *projectRole) grantThisRoleScope() (*RoleGrantScope, bool) {
	if p == nil {
		return &RoleGrantScope{}, false
	}
	if !p.GrantThisRoleScope {
		return &RoleGrantScope{}, false
	}
	return &RoleGrantScope{
		CreateTime:       p.GrantThisRoleScopeUpdateTime,
		RoleId:           p.PublicId,
		ScopeIdOrSpecial: globals.GrantScopeThis,
	}, true
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
