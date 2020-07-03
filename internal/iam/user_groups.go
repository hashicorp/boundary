package iam

import (
	"context"
	"errors"

	"github.com/hashicorp/watchtower/internal/db"
)

// Groups will get the user's groups
func (u *User) Groups(ctx context.Context, r db.Reader) ([]*Group, error) {
	const where = "public_id in (select distinct group_id from iam_group_member_user where member_id = ?)"

	if r == nil {
		return nil, errors.New("error reader is nil for getting the user's groups")
	}
	if u.PublicId == "" {
		return nil, errors.New("error user id is unset for finding user groups")
	}
	groups := []*Group{}
	if err := r.SearchWhere(ctx, &groups, where, []interface{}{u.PublicId}); err != nil {
		return nil, err
	}
	return groups, nil
}
