package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

// AddMember will create a new in memory GroupMember
func (g *Group) AddMember(ctx context.Context, r db.Reader, m Resource, opt ...db.Option) (GroupMember, error) {
	gm, err := NewGroupMember(g, m)
	if err != nil {
		return nil, err
	}
	return gm, nil
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
