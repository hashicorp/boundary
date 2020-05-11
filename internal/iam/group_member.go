package iam

import (
	"context"
	"errors"

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

// GroupMember declares a common interface for all members assigned to a group (which is just users for now)
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

// NewGroupMember creates a new member of the group with a scope (project/organization)
// options include: withDescripion, WithName
func NewGroupMember(g *Group, m Resource, opt ...Option) (GroupMember, error) {
	if g == nil {
		return nil, errors.New("error group is nil for group member")
	}
	if g.PublicId == "" {
		return nil, errors.New("error group id is unset for group member")
	}
	if m == nil {
		return nil, errors.New("member is nil for group member")
	}
	if m.ResourceType() == ResourceTypeUser {
		if u, ok := m.(*User); ok {
			return newGroupMemberUser(g, u, opt...)
		}
		return nil, errors.New("error group member is not a user ptr")
	}
	return nil, errors.New("error unknown group member type")
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

// newGroupMemberUser creates a new user member of the group
// options include: withDescripion, WithName
func newGroupMemberUser(g *Group, m *User, opt ...Option) (GroupMember, error) {
	if m == nil {
		return nil, errors.New("error the user member is nil")
	}
	if m.PublicId == "" {
		return nil, errors.New("error the user member id is unset")
	}
	if g == nil {
		return nil, errors.New("error the user member group is nil")
	}
	if g.PublicId == "" {
		return nil, errors.New("error the user member group is unset")
	}
	gm := &GroupMemberUser{
		GroupMemberUser: &store.GroupMemberUser{
			MemberId: m.PublicId,
			GroupId:  g.PublicId,
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
