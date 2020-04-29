package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// User defines watchtower users which are scoped to an Organization
type User struct {
	*store.User
	tableName string `gorm:"-"`
}

// ensure that User implements the interfaces of: Resource, ClonableResource and db.VetForWriter
var _ Resource = (*User)(nil)
var _ ClonableResource = (*User)(nil)
var _ db.VetForWriter = (*User)(nil)

// NewUser creates a new user and allows options:
// withFriendlyName - to specify the user's friendly name
func NewUser(primaryScope *Scope, opt ...Option) (*User, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if primaryScope == nil {
		return nil, errors.New("error user primary scope is nil")
	}
	if primaryScope.Type != OrganizationScope.String() {
		return nil, errors.New("users can only be within an organization scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public ID %w for new user", err)
	}
	u := &User{
		User: &store.User{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
		},
	}
	if withFriendlyName != "" {
		u.FriendlyName = withFriendlyName
	}
	return u, nil
}

func allocUser() User {
	return User{
		User: &store.User{},
	}
}

// Clone creates a clone of the User
func (u *User) Clone() Resource {
	cp := proto.Clone(u.User)
	return &User{
		User: cp.(*store.User),
	}
}

// Roles gets the roles for the user (we should/can support options to include roles associated with the user's groups)
func (u *User) Roles(ctx context.Context, r db.Reader, opt ...Option) (map[string]*Role, error) {
	if u.Id == 0 {
		return nil, errors.New("error user id is 0 for finding roles")
	}
	where := "id in (select role_id from iam_assigned_role_vw ipr where principal_id  = ? and type = ?)"
	roles := []*Role{}
	if err := r.SearchBy(ctx, &roles, where, u.Id, UserRoleType.String()); err != nil {
		return nil, fmt.Errorf("error getting user roles %w", err)
	}
	results := map[string]*Role{}
	for _, r := range roles {
		results[r.PublicId] = r
	}
	return results, nil
}

// Grants finds the grants for the user and supports options:
// WithGroupGrants which will get the grants assigned to the user's groups as well
func (u *User) Grants(ctx context.Context, r db.Reader, opt ...Option) ([]*RoleGrant, error) {
	opts := GetOpts(opt...)
	withGrpGrants := opts[optionWithGroupGrants].(bool)
	if u.Id == 0 {
		return nil, errors.New("error user id is 0 for finding roles")
	}
	grants := []*RoleGrant{}
	// client just wants the grants directly granted to the user
	if !withGrpGrants {
		where := "role_id in (select role_id from iam_assigned_role_vw ipr where principal_id  = ? and type = ?)"
		if err := r.SearchBy(ctx, &grants, where, u.Id, UserRoleType.String()); err != nil {
			return nil, fmt.Errorf("error getting user roles %w", err)
		}
		return grants, nil
	}

	if withGrpGrants {
		// okay, we're going to get the user grants and include the grants from any group the user is part of.
		tx, err := r.DB()
		if err != nil {
			return nil, err
		}
		where := `
select 
  rg.*
from
  iam_role_grant rg,
  iam_assigned_role_vw ipr, 
  iam_group grp, 
  iam_group_member gm 
where 
  rg.role_id = ipr.role_id and 
  ipr.principal_id = grp.id and 
  grp.id = gm.group_id and 
  gm.member_id = $1 and gm.type = 'user' and
  ipr."type" = 'group'
union
select 
  rg.*
from 
  iam_role_grant rg,
  iam_assigned_role_vw ipr 
where 
  ipr.role_id  = rg.role_id and 
  ipr.principal_id  = $2 and ipr.type = 'user'`

		rows, err := tx.Query(where, u.Id, u.Id)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			g := allocRoleGrant()
			if err := r.ScanRows(rows, &g); err != nil {
				return nil, err
			}
			grants = append(grants, &g)
		}
	}
	return grants, nil
}

func (u *User) Groups(ctx context.Context, r db.Reader) ([]*Group, error) {
	if u.Id == 0 {
		return nil, errors.New("error user id is 0 for finding user groups")
	}
	where := "id in (select distinct group_id from iam_group_member where member_id = ? and type = ?)"
	groups := []*Group{}
	if err := r.SearchBy(ctx, &groups, where, u.Id, UserMemberType.String()); err != nil {
		return nil, fmt.Errorf("error finding user groups: %w", err)
	}
	return groups, nil
}

// VetForWrite implements db.VetForWrite() interface
func (u *User) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if u.PublicId == "" {
		return errors.New("error public id is empty string for user write")
	}
	if u.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for user write")
	}
	// make sure the scope is valid for users
	if err := u.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (u *User) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, u)
	if err != nil {
		return err
	}
	if ps.Type != OrganizationScope.String() {
		return errors.New("error primary scope is not an organization")
	}
	return nil
}

// GetPrimaryScope returns the PrimaryScope for the User
func (u *User) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, u)
}

// ResourceType returns the type of the User
func (*User) ResourceType() ResourceType { return ResourceTypeUser }

// Actions returns the  available actions for Users
func (*User) Actions() map[string]Action {
	return StdActions()
}

// TableName returns the tablename to override the default gorm table name
func (u *User) TableName() string {
	if u.tableName != "" {
		return u.tableName
	}
	return "iam_user"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (u *User) SetTableName(n string) {
	if n != "" {
		u.tableName = n
	}
}
