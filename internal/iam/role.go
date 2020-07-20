package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/protobuf/proto"
)

const (
	defaultRoleTableName = "iam_role"
)

// Roles are granted permissions and assignable to Users and Groups.
type Role struct {
	*store.Role
	tableName string `gorm:"-"`
}

// ensure that Role implements the interfaces of: Resource, Clonable, and db.VetForWriter.
var _ Resource = (*Role)(nil)
var _ Clonable = (*Role)(nil)
var _ db.VetForWriter = (*Role)(nil)

// NewRole creates a new in memory role with a scope (project/org)
// allowed options include: withDescripion, WithName, withGrantScopeId.
func NewRole(scopeId string, opt ...Option) (*Role, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new role: missing scope id %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	r := &Role{
		Role: &store.Role{
			ScopeId:      scopeId,
			Name:         opts.withName,
			Description:  opts.withDescription,
			GrantScopeId: opts.withGrantScopeId,
		},
	}
	return r, nil
}

func allocRole() Role {
	return Role{
		Role: &store.Role{},
	}
}

// Clone creates a clone of the Role.
func (r *Role) Clone() interface{} {
	cp := proto.Clone(r.Role)
	return &Role{
		Role: cp.(*store.Role),
	}
}

// VetForWrite implements db.VetForWrite() interface.
func (role *Role) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if role.PublicId == "" {
		return errors.New("error public id is empty string for role write")
	}
	if err := validateScopeForWrite(ctx, r, role, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (u *Role) validScopeTypes() []scope.Type {
	return []scope.Type{scope.Org, scope.Project}
}

// Getscope returns the scope for the Role.
func (role *Role) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, role)
}

// ResourceType returns the type of the Role.
func (*Role) ResourceType() resource.Type { return resource.Role }

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
func (r *Role) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return defaultRoleTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (r *Role) SetTableName(n string) {
	switch n {
	case "":
		r.tableName = defaultRoleTableName
	default:
		r.tableName = n
	}
}
