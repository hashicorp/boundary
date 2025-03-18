// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

const (
	defaultRoleTableName = "iam_role"
)

// Role is a set of granted permissions and assignable to Users and Groups.
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

type globalRole struct {
	*store.GlobalRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
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

type orgRole struct {
	*store.OrgRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
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

type projectRole struct {
	*store.ProjectRole
	GrantScopes []*RoleGrantScope `gorm:"-"`
	tableName   string            `gorm:"-"`
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

// ensure that Role implements the interfaces of: Resource, Cloneable, and db.VetForWriter.
var (
	_ Resource        = (*globalRole)(nil)
	_ Cloneable       = (*globalRole)(nil)
	_ db.VetForWriter = (*globalRole)(nil)

	_ Resource        = (*orgRole)(nil)
	_ Cloneable       = (*orgRole)(nil)
	_ db.VetForWriter = (*orgRole)(nil)

	_ Resource        = (*projectRole)(nil)
	_ Cloneable       = (*projectRole)(nil)
	_ db.VetForWriter = (*projectRole)(nil)
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

func allocRole() Role {
	return Role{}
}

type deletedRole struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedRole) TableName() string {
	return "iam_role_deleted"
}
