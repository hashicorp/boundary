package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// Group is made up of members and can be assigned roles
type Group struct {
	*store.Group
	tableName string `gorm:"-"`
}

// ensure that Group implements the interfaces of: Resource, Clonable, and db.VetForWriter
var _ Resource = (*Group)(nil)
var _ Clonable = (*Group)(nil)
var _ db.VetForWriter = (*Group)(nil)

// NewGroup creates a new in memory group with a scope (project/organization)
// options include: withDescripion, WithName
func NewGroup(scopeId string, opt ...Option) (*Group, error) {
	opts := getOpts(opt...)
	withName := opts.withName
	withDescription := opts.withDescription
	if scopeId == "" {
		return nil, errors.New("error organization id is unset for new group")
	}
	publicId, err := db.NewPublicId("g")
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new group", err)
	}
	g := &Group{
		Group: &store.Group{
			PublicId:    publicId,
			ScopeId:     scopeId,
			Name:        withName,
			Description: withDescription,
		},
	}
	return g, nil
}

// Clone creates a clone of the Group
func (g *Group) Clone() interface{} {
	cp := proto.Clone(g.Group)
	return &Group{
		Group: cp.(*store.Group),
	}
}

func allocGroup() Group {
	return Group{
		Group: &store.Group{},
	}
}

// Members returns the members of the group (Users)
func (g *Group) Members(ctx context.Context, r db.Reader) ([]GroupMember, error) {
	const where = "group_id = ? and type = ?"
	viewMembers := []*groupMemberView{}
	if err := r.SearchWhere(ctx, &viewMembers, where, g.PublicId, UserMemberType.String()); err != nil {
		return nil, err
	}

	members := []GroupMember{}
	for _, m := range viewMembers {
		switch m.Type {
		case UserMemberType.String():
			gm := &GroupMemberUser{
				GroupMemberUser: &store.GroupMemberUser{
					CreateTime: m.CreateTime,
					GroupId:    m.GroupId,
					MemberId:   m.MemberId,
				},
			}
			members = append(members, gm)
		default:
			return nil, fmt.Errorf("error unsupported member type: %s", m.Type)
		}

	}
	return members, nil
}

// AddMember will create a new in memory GroupMember
func (g *Group) AddMember(ctx context.Context, r db.Reader, m Resource, opt ...db.Option) (GroupMember, error) {
	gm, err := NewGroupMember(g, m)
	if err != nil {
		return nil, err
	}
	return gm, nil
}

// VetForWrite implements db.VetForWrite() interface and validates the group
// before it's written
func (g *Group) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if g.PublicId == "" {
		return errors.New("error public id is empty string for group write")
	}
	if err := validateScopeForWrite(ctx, r, g, opType, opt...); err != nil {
		return err
	}
	return nil
}

func (u *Group) validScopeTypes() []ScopeType {
	return []ScopeType{OrganizationScope, ProjectScope}
}

// GetScope returns the scope for the Group
func (g *Group) GetScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupScope(ctx, r, g)
}

// ResourceType returns the type of the Group
func (*Group) ResourceType() ResourceType { return ResourceTypeGroup }

// Actions returns the  available actions for Group
func (*Group) Actions() map[string]Action {
	return CrudActions()
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
