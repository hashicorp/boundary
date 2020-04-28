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

// Group is made up of members (users for now) and can be assigned roles
type Group struct {
	*store.Group
	tableName string `gorm:"-"`
}

// ensure that Group implements the interfaces of: Resource, ClonableResource, and db.VetForWriter
var _ Resource = (*Group)(nil)
var _ ClonableResource = (*Group)(nil)
var _ db.VetForWriter = (*Group)(nil)

// NewGroup creates a new group with a scope (project/organization)
// options include: withDescripion, withFriendlyName
func NewGroup(primaryScope *Scope, opt ...Option) (*Group, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	withDescription := opts[optionWithDescription].(string)
	if primaryScope == nil {
		return nil, errors.New("error the group primary scope is nil")
	}
	if primaryScope.Type != OrganizationScope.String() &&
		primaryScope.Type != ProjectScope.String() {
		return nil, errors.New("groups can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new group", err)
	}
	g := &Group{
		Group: &store.Group{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
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

// Clone creates a clone of the Group
func (g *Group) Clone() Resource {
	cp := proto.Clone(g.Group)
	return &Group{
		Group: cp.(*store.Group),
	}
}

// Members returns the members of the group (Users)
func (g *Group) Members(ctx context.Context, r db.Reader) ([]GroupMember, error) {
	viewMembers := []*groupMemberView{}
	if err := r.SearchBy(ctx, &viewMembers, "group_id = ? and type = ?", g.Id, UserMemberType.String()); err != nil {
		return nil, fmt.Errorf("error getting group members %w", err)
	}

	members := []GroupMember{}
	for _, m := range viewMembers {
		switch m.Type {
		case UserMemberType.String():
			gm := &GroupMemberUser{
				GroupMemberUser: &store.GroupMemberUser{
					Id:             m.Id,
					CreateTime:     m.CreateTime,
					UpdateTime:     m.UpdateTime,
					PublicId:       m.PublicId,
					FriendlyName:   m.FriendlyName,
					PrimaryScopeId: m.PrimaryScopeId,
					GroupId:        m.GroupId,
					Type:           UserMemberType.String(),
					MemberId:       m.MemberId,
				},
			}
			members = append(members, gm)
		default:
			return nil, fmt.Errorf("error unsupported member type: %s", m.Type)
		}

	}
	return members, nil
}

// AddMember will add member to the group and the caller is responsible for Creating that Member via db.Writer.Create()
func (g *Group) AddMember(ctx context.Context, r db.Reader, m Resource, opt ...db.Option) (GroupMember, error) {
	ps, err := g.GetPrimaryScope(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("error getting primary scope while adding member: %w", err)
	}
	gm, err := NewGroupMember(ps, g, m)
	if err != nil {
		return nil, fmt.Errorf("error while adding member %w", err)
	}
	return gm, nil
}

// VetForWrite implements db.VetForWrite() interface
func (g *Group) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if g.PublicId == "" {
		return errors.New("error public id is empty string for group write")
	}
	if g.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for group write")
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
	if ps.Type != OrganizationScope.String() && ps.Type != ProjectScope.String() {
		return errors.New("error primary scope is not an organization or project for group")
	}
	return nil
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
