package oidc

const (
	findManagedGroupMembershipsForAccount = `
	select
		managed_group_id
	from
		auth_oidc_managed_group_member_account
	where
		member_id = $1`
)
