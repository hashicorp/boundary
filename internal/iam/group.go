package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

type Group struct {
	*store.Group
	tableName string `gorm:"-"`
}

var _ Resource = (*Group)(nil)

var _ db.VetForWriter = (*Group)(nil)

// NewGroup creates a new group with a scope (project/organization), owner (user)
// options include: withDescripion, withFriendlyName
func NewGroup(primaryScope *Scope, owner *User, opt ...Option) (*Group, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	withDescription := opts[optionWithDescription].(string)
	if primaryScope == nil {
		return nil, errors.New("error the role primary scope is nil")
	}
	if owner == nil {
		return nil, errors.New("error the role owner is nil")
	}
	if owner.Id == 0 {
		return nil, errors.New("error the role owner id == 0")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new role", err)
	}
	g := &Group{
		Group: &store.Group{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			OwnerId:        owner.Id,
		},
	}
	if withFriendlyName != "" {
		g.FriendlyName = withFriendlyName
	}
	if optionWithDescription != "" {
		g.Description = withDescription
	}
	return g, nil
}

// Members returns the members of the group (Users or UserAlias)
func (g *Group) Members(ctx context.Context, r db.Reader) ([]GroupMember, error) {
	viewMembers := []*groupMemberView{}
	if err := r.SearchBy(ctx, &viewMembers, "group_id = ? and type in(?, ?)", g.Id, UserMemberType, UserAliasMemberType); err != nil {
		return nil, fmt.Errorf("error getting group members %w", err)
	}

	members := []GroupMember{}
	for _, m := range viewMembers {
		switch m.Type {
		case uint32(UserMemberType):
			gm := &GroupMemberUser{
				GroupMemberUser: &store.GroupMemberUser{
					Id:             m.Id,
					CreateTime:     m.CreateTime,
					UpdateTime:     m.UpdateTime,
					PublicId:       m.PublicId,
					FriendlyName:   m.FriendlyName,
					PrimaryScopeId: m.PrimaryScopeId,
					OwnerId:        m.OwnerId,
					GroupId:        m.GroupId,
					Type:           uint32(UserMemberType),
					MemberId:       m.Id,
				},
			}
			members = append(members, gm)
		case uint32(UserAliasMemberType):
			gm := &GroupMemberUser{
				GroupMemberUser: &store.GroupMemberUser{
					Id:             m.Id,
					CreateTime:     m.CreateTime,
					UpdateTime:     m.UpdateTime,
					PublicId:       m.PublicId,
					FriendlyName:   m.FriendlyName,
					PrimaryScopeId: m.PrimaryScopeId,
					OwnerId:        m.OwnerId,
					GroupId:        m.GroupId,
					Type:           uint32(UserMemberType),
					MemberId:       m.Id,
				},
			}
			members = append(members, gm)
		default:
			return nil, fmt.Errorf("error unsupported member type: %d", m.Type)
		}

	}
	return members, nil
}

// VetForWrite implements db.VetForWrite() interface
func (g *Group) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if g.PublicId == "" {
		return errors.New("error public id is empty string for group write")
	}
	if g.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for group write")
	}
	if g.OwnerId == 0 {
		return errors.New("error owner id == 0 for group write")
	}
	// make sure the scope is valid for users
	if err := g.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (g *Group) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, g)
	if err != nil {
		return err
	}
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization or project for group")
	}
	return nil
}

// GetOwner returns the owner (User) of the Group
func (g *Group) GetOwner(ctx context.Context, r db.Reader) (*User, error) {
	return LookupOwner(ctx, r, g)
}

// GetPrimaryScope returns the PrimaryScope for the Group
func (g *Group) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, g)
}

// ResourceType returns the type of the Group
func (*Group) ResourceType() ResourceType { return ResourceTypeGroup }

// Actions returns the  available actions for Group
func (*Group) Actions() map[string]Action {
	return StdActions()
}

// TableName returns the tablename to override the default gorm table name
func (g *Group) TableName() string {
	if g.tableName != "" {
		return g.tableName
	}
	return "iam_group"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (g *Group) SetTableName(n string) {
	if n != "" {
		g.tableName = n
	}
}
