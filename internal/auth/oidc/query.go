package oidc

const (
	acctUpsertQuery = `
	insert into auth_oidc_account
			(%s)
	values
			(%s)
	on conflict on constraint 
			auth_oidc_account_auth_method_id_issuer_subject_uq
	do update set
			%s
	returning public_id, version
       `

	findManagedGroupMembershipsForAccount = `
	select
		managed_group_id
	from
		auth_oidc_managed_group_member_account
	where
		member_id = $1`
)
