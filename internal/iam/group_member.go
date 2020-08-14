package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// MemberType defines the possible membership types for groups. We don't surface
// this in the API as of yet as it's always user and we don't have plans for
// others currently.
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

const (
	groupMemberViewDefaultTableName = "iam_group_member"
	groupMemberUserDefaultTable     = "iam_group_member_user"
)

// GroupMember provides a common way to return members.
type GroupMember struct {
	*store.GroupMemberView
	tableName string `gorm:"-"`
}

// TableName provides an overridden gorm table name for group members.
func (v *GroupMember) TableName() string {
	if v.tableName != "" {
		return v.tableName
	}
	return groupMemberViewDefaultTableName
}

// SetTableName sets the table name for the resource.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (v *GroupMember) SetTableName(n string) {
	switch n {
	case "":
		v.tableName = groupMemberViewDefaultTableName
	default:
		v.tableName = n
	}
}

// GroupMemberUser is a group member that's a User
type GroupMemberUser struct {
	*store.GroupMemberUser
	tableName string `gorm:"-"`
}

// ensure that GroupMember implements the interfaces of: Cloneable, db.VetForWriter
var _ Cloneable = (*GroupMemberUser)(nil)
var _ db.VetForWriter = (*GroupMemberUser)(nil)

// NewGroupMemberUser creates a new in memory user member of the group. No
// options are currently supported.
func NewGroupMemberUser(groupId, userId string, opt ...Option) (*GroupMemberUser, error) {
	if groupId == "" {
		return nil, fmt.Errorf("new group member: missing group id: %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return nil, fmt.Errorf("new group member: missing user id: %w", db.ErrInvalidParameter)
	}
	return &GroupMemberUser{
		GroupMemberUser: &store.GroupMemberUser{
			MemberId: userId,
			GroupId:  groupId,
		},
	}, nil
}

func allocGroupMember() GroupMemberUser {
	return GroupMemberUser{
		GroupMemberUser: &store.GroupMemberUser{},
	}
}

// Clone creates a clone of the GroupMember
func (m *GroupMemberUser) Clone() interface{} {
	cp := proto.Clone(m.GroupMemberUser)
	return &GroupMemberUser{
		GroupMemberUser: cp.(*store.GroupMemberUser),
	}
}

// VetForWrite implements db.VetForWrite() interface for group members.
func (m *GroupMemberUser) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if m.GroupId == "" {
		return fmt.Errorf("group member: missing group id: %w", db.ErrInvalidParameter)
	}
	if m.MemberId == "" {
		return fmt.Errorf("group member: missing member id: %w", db.ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (m *GroupMemberUser) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return groupMemberUserDefaultTable
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (m *GroupMemberUser) SetTableName(n string) {
	switch n {
	case "":
		m.tableName = groupMemberUserDefaultTable
	default:
		m.tableName = n
	}
}
