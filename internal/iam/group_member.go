package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// MemberType defines the possible types for members
type MemberType uint32

const (
	UnknownMemberType MemberType = 0
	UserMemberType    MemberType = 1
)

func (m MemberType) String() string {
	return [...]string{
		"unknown",
		"user",
	}[m]
}

// GroupMember declares a common interface for all members assigned to a group
type GroupMember interface {
	GetGroupId() string
	GetMemberId() string
	GetType() string
}

// groupMemberView provides a common way to return group members regardless of their underlying type
type groupMemberView struct {
	*store.GroupMemberView
}

// TableName provides an overridden gorm table name for group members
func (v *groupMemberView) TableName() string { return "iam_group_member" }

// AddUser will add a user to the group in memory, returning a GroupMember that
// can be written to the db
func (g *Group) AddUser(userId string, opt ...db.Option) (GroupMember, error) {
	gm, err := newGroupMemberUser(g.PublicId, userId)
	if err != nil {
		return nil, err
	}
	return gm, nil
}

// Members returns the members of the group (Users)
func (g *Group) Members(ctx context.Context, r db.Reader) ([]GroupMember, error) {
	const where = "group_id = ? and type = ?"
	viewMembers := []*groupMemberView{}
	if err := r.SearchWhere(ctx, &viewMembers, where, []interface{}{g.PublicId, UserMemberType.String()}); err != nil {
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

// GroupMemberUser is a group member that's a User
type GroupMemberUser struct {
	*store.GroupMemberUser
	tableName string `gorm:"-"`
}

// ensure that GroupMemberUser implements the interfaces of: Clonable, GroupMember and db.VetForWriter
var _ Clonable = (*GroupMemberUser)(nil)
var _ GroupMember = (*GroupMemberUser)(nil)
var _ db.VetForWriter = (*GroupMemberUser)(nil)

// newGroupMemberUser creates a new in memory user member of the group
// options include: withDescripion, WithName
func newGroupMemberUser(groupId, userId string, opt ...Option) (*GroupMemberUser, error) {
	if userId == "" {
		return nil, errors.New("error the user public id is unset")
	}
	if groupId == "" {
		return nil, errors.New("error the user member group is unset")
	}
	gm := &GroupMemberUser{
		GroupMemberUser: &store.GroupMemberUser{
			MemberId: userId,
			GroupId:  groupId,
		},
	}
	return gm, nil
}

func (m *GroupMemberUser) GetType() string {
	return UserMemberType.String()
}

func allocGroupMemberUser() GroupMemberUser {
	return GroupMemberUser{
		GroupMemberUser: &store.GroupMemberUser{},
	}
}

// Clone creates a clone of the GroupMemberUser
func (m *GroupMemberUser) Clone() interface{} {
	cp := proto.Clone(m.GroupMemberUser)
	return &GroupMemberUser{
		GroupMemberUser: cp.(*store.GroupMemberUser),
	}
}

// VetForWrite implements db.VetForWrite() interface
func (m *GroupMemberUser) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (m *GroupMemberUser) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return "iam_group_member_user"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (m *GroupMemberUser) SetTableName(n string) {
	if n != "" {
		m.tableName = n
	}
}
