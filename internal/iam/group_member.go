package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

// MemberType defines the possible types for members
type MemberType uint32

const (
	UnknownMemberType MemberType = 0
	UserMemberType    MemberType = 1
)

type GroupMember interface {
	Resource
	GetGroupId() uint32
	GetMemberId() uint32
	GetType() uint32
}

type groupMemberView struct {
	*store.GroupMemberView
}

func (v *groupMemberView) TableName() string { return "iam_group_member" }

// NewGroupMember creates a new member of the group with a scope (project/organization)
// options include: withDescripion, withFriendlyName
func NewGroupMember(primaryScope *Scope, g *Group, m Resource, opt ...Option) (GroupMember, error) {
	if m.ResourceType() == ResourceTypeUser {
		if u, ok := m.(*User); ok {
			return NewGroupMemberUser(primaryScope, g, u, opt...)
		}
		return nil, errors.New("error group member is not a user ptr")
	}
	return nil, errors.New("error unknown group member type")
}

type GroupMemberUser struct {
	*store.GroupMemberUser
	tableName string `gorm:"-"`
}

var _ Resource = (*GroupMemberUser)(nil)
var _ GroupMember = (*GroupMemberUser)(nil)
var _ db.VetForWriter = (*GroupMemberUser)(nil)

// NewGroupMemberUser creates a new user member of the groupwith a scope (project/organization)
// options include: withDescripion, withFriendlyName
func NewGroupMemberUser(primaryScope *Scope, g *Group, m *User, opt ...Option) (GroupMember, error) {
	opts := GetOpts(opt...)
	withFriendlyName := opts[optionWithFriendlyName].(string)
	if primaryScope == nil {
		return nil, errors.New("error the user member primary scope is nil")
	}
	if m == nil {
		return nil, errors.New("error the user member is nil")
	}
	if m.Id == 0 {
		return nil, errors.New("error the user member id == 0")
	}
	if g == nil {
		return nil, errors.New("error the user member group is nil")
	}
	if g.Id == 0 {
		return nil, errors.New("error the user member group == 0")
	}
	if primaryScope.Type != uint32(OrganizationScope) &&
		primaryScope.Type != uint32(ProjectScope) {
		return nil, errors.New("roles can only be within an organization or project scope")
	}
	publicId, err := base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("error generating public id %w for new user member", err)
	}
	gm := &GroupMemberUser{
		GroupMemberUser: &store.GroupMemberUser{
			PublicId:       publicId,
			PrimaryScopeId: primaryScope.GetId(),
			MemberId:       m.Id,
			GroupId:        g.Id,
			Type:           uint32(UserMemberType),
		},
	}
	if withFriendlyName != "" {
		gm.FriendlyName = withFriendlyName
	}
	return gm, nil
}

// VetForWrite implements db.VetForWrite() interface
func (m *GroupMemberUser) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType) error {
	if m.PublicId == "" {
		return errors.New("error public id is empty string for group write")
	}
	if m.PrimaryScopeId == 0 {
		return errors.New("error primary scope id not set for group write")
	}
	if m.Type != uint32(UserMemberType) {
		return errors.New("error member type is not user")
	}
	// make sure the scope is valid for users
	if err := m.primaryScopeIsValid(ctx, r); err != nil {
		return err
	}
	return nil
}

func (m *GroupMemberUser) primaryScopeIsValid(ctx context.Context, r db.Reader) error {
	ps, err := LookupPrimaryScope(ctx, r, m)
	if err != nil {
		return err
	}
	if ps.Type != uint32(OrganizationScope) && ps.Type != uint32(ProjectScope) {
		return errors.New("error primary scope is not an organization or project for user group member")
	}
	return nil
}

// GetPrimaryScope returns the PrimaryScope for the GroupMember
func (m *GroupMemberUser) GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error) {
	return LookupPrimaryScope(ctx, r, m)
}

// ResourceType returns the type of the GroupMember
func (*GroupMemberUser) ResourceType() ResourceType { return ResourceTypeGroupMember }

// Actions returns the  available actions for GroupMember
func (*GroupMemberUser) Actions() map[string]Action {
	return StdActions()
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
