package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"google.golang.org/protobuf/proto"
)

// GroupMember is a group member that's a User
type GroupMember struct {
	*store.GroupMember
	tableName string `gorm:"-"`
}

// ensure that GroupMember implements the interfaces of: Clonable, db.VetForWriter
var _ Clonable = (*GroupMember)(nil)
var _ db.VetForWriter = (*GroupMember)(nil)

// NewGroupMember creates a new in memory user member of the group.  Users can
// be assigned to groups which are within its organization, or the group is
// within a project within its organization. This relationship will not be
// enforced until the group member is written to the database. No options are
// currently supported.
func NewGroupMember(groupId, userId string, opt ...Option) (*GroupMember, error) {
	if groupId == "" {
		return nil, fmt.Errorf("new group member: missing group id: %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return nil, fmt.Errorf("new group member: missing user id: %w", db.ErrInvalidParameter)
	}
	return &GroupMember{
		GroupMember: &store.GroupMember{
			MemberId: userId,
			GroupId:  groupId,
		},
	}, nil
}

func allocGroupMember() GroupMember {
	return GroupMember{
		GroupMember: &store.GroupMember{},
	}
}

// Clone creates a clone of the GroupMember
func (m *GroupMember) Clone() interface{} {
	cp := proto.Clone(m.GroupMember)
	return &GroupMember{
		GroupMember: cp.(*store.GroupMember),
	}
}

// VetForWrite implements db.VetForWrite() interface for group members.
func (m *GroupMember) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if m.GroupId == "" {
		return fmt.Errorf("group member: missing group id: %w", db.ErrInvalidParameter)
	}
	if m.MemberId == "" {
		return fmt.Errorf("group member: missing member id: %w", db.ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (m *GroupMember) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return "iam_group_member"
}

// SetTableName sets the tablename and satisfies the ReplayableMessage interface
func (m *GroupMember) SetTableName(n string) {
	if n != "" {
		m.tableName = n
	}
}
