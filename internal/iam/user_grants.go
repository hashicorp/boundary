package iam

import (
	"context"
	"errors"

	"github.com/hashicorp/watchtower/internal/db"
)

// Grants finds the grants for the user and supports options:
// WithGroupGrants which will get the grants assigned to the user's groups as well
func (u *User) Grants(ctx context.Context, r db.Reader, opt ...Option) ([]*RoleGrant, error) {
	const (
		whereBase = `
role_id in (select role_id from iam_principal_role ipr where principal_id  = ? and type = ?)
`

		whereWithGrpGrants = `
select 
	rg.*
from
	iam_role_grant rg,
	iam_principal_role ipr, 
	iam_group grp, 
	iam_group_member gm 
where 
	rg.role_id = ipr.role_id and 
	ipr.principal_id = grp.public_id and 
	grp.public_id = gm.group_id and 
	gm.member_id = $1 and gm.type = 'user' and
	ipr."type" = 'group'
union
select 
	rg.*
from 
	iam_role_grant rg,
	iam_principal_role ipr 
where 
	ipr.role_id  = rg.role_id and 
	ipr.principal_id  = $2 and ipr.type = 'user'
`
	)
	if r == nil {
		return nil, errors.New("error reader is nil for getting the user's grants")
	}
	opts := getOpts(opt...)
	withGrpGrants := opts.withGroupGrants
	if u.PublicId == "" {
		return nil, errors.New("error user id is unset for finding roles")
	}
	if withGrpGrants {
		grants := []*RoleGrant{}
		tx, err := r.DB()
		if err != nil {
			return nil, err
		}
		rows, err := tx.Query(whereWithGrpGrants, u.PublicId, u.PublicId)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			g := allocRoleGrant()
			if err := r.ScanRows(rows, &g); err != nil {
				return nil, err
			}
			grants = append(grants, &g)
		}
		return grants, nil
	}

	grants := []*RoleGrant{}
	if err := r.SearchWhere(ctx, &grants, whereBase, []interface{}{u.PublicId, UserRoleType.String()}); err != nil {
		return nil, err
	}
	return grants, nil

}
