package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
)

// AssignedRoles returns a list of principal roles (Users and Groups) for the Role.
func (role *Role) AssignedRoles(ctx context.Context, r db.Reader) ([]PrincipalRole, error) {
	viewRoles := []*principalRoleView{}
	if err := r.SearchWhere(
		ctx,
		&viewRoles,
		"role_id = ? and type in(?, ?)",
		[]interface{}{role.PublicId, UserRoleType.String(), GroupRoleType.String()}); err != nil {
		return nil, fmt.Errorf("error getting assigned roles %w", err)
	}

	pRoles := []PrincipalRole{}
	for _, vr := range viewRoles {
		switch vr.Type {
		case UserRoleType.String():
			pr := &UserRole{
				UserRole: &store.UserRole{
					CreateTime:  vr.CreateTime,
					RoleId:      vr.RoleId,
					PrincipalId: vr.PrincipalId,
				},
			}
			pRoles = append(pRoles, pr)
		case GroupRoleType.String():
			pr := &GroupRole{
				GroupRole: &store.GroupRole{
					CreateTime:  vr.CreateTime,
					RoleId:      vr.RoleId,
					PrincipalId: vr.PrincipalId,
				},
			}
			pRoles = append(pRoles, pr)
		default:
			return nil, fmt.Errorf("error unsupported role type: %s", vr.Type)
		}
	}
	return pRoles, nil
}
