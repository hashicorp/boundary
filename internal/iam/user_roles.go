package iam

import (
	"context"
	"errors"

	"github.com/hashicorp/watchtower/internal/db"
)

// Roles gets the roles for the user (we should/can support options to include roles associated with the user's groups)
func (u *User) Roles(ctx context.Context, r db.Reader, opt ...Option) (map[string]*Role, error) {
	const where = "public_id in (select role_id from iam_principal_role ipr where principal_id  = ? and type = ?)"

	if r == nil {
		return nil, errors.New("reader is nil for getting the user's roles")
	}
	if u.PublicId == "" {
		return nil, errors.New("error user id is unset for finding roles")
	}
	roles := []*Role{}
	if err := r.SearchWhere(ctx, &roles, where, u.PublicId, UserRoleType.String()); err != nil {
		return nil, err
	}
	results := map[string]*Role{}
	for _, r := range roles {
		results[r.PublicId] = r
	}
	return results, nil
}
