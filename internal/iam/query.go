// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

// query.go contains "raw sql" for the iam package that goes directly against
// the db via sql.DB vs the standard pattern of using the internal/db package to
// interact with the db.
const (
	// whereUserAccount - given an auth account id, return the associated user.
	whereUserAccount = `	
	select iam_user_acct_info.*
		from iam_user_acct_info 
	inner join auth_account 
		on iam_user_acct_info.public_id = auth_account.iam_user_id
	where 
		iam_user_acct_info.scope_id = auth_account.scope_id and
		auth_account.public_id = ?`

	// whereValidAuthMethod - determine if an auth method public_id within a scope_id
	// is valid by returning a count of matching rows.
	whereValidAuthMethod = `select count(*) from auth_method where public_id = $1 and scope_id = $2` // raw query

	// insertAuthMethod - insert a row directly into auth_method (TODO - this
	// should be replaced with calls to the auth method repo).
	insertAuthMethod = `insert into auth_method (public_id, scope_id) values (?, ?)`

	accountChangesQuery = `
	with
	final_accounts (account_id) as (
	  -- returns the SET list
	  select public_id
		from auth_account
	   where public_id in (%s)
	),
	current_accounts (account_id) as (
	  -- returns the current list
	  select public_id
		from auth_account
	   where iam_user_id = ?
	),
	keep_accounts (account_id) as (
	  -- returns the KEEP list
	  select account_id
		from current_accounts
	   where account_id in (select * from final_accounts)
	),
	delete_accounts (account_id) as (
	  -- returns the DELETE list
	  select account_id
		from current_accounts
	   where account_id not in (select * from final_accounts)
	),
	insert_accounts (account_id) as (
	  -- returns the ADD list
	  select account_id
		from final_accounts
	   where account_id not in (select * from keep_accounts)
	),
	final (action, account_id) as (
	  select 'disassociate', account_id
		from delete_accounts
	   union
	  select 'associate', account_id
		from insert_accounts
	)
	select * from final
	order by action, account_id;
	`

	grpMemberChangesQuery = `
	with
	final_members (member_id) as (
	  -- returns the SET list
	  select public_id
		from iam_user
	   where
	   	public_id in (%s)
	),
	current_members (member_id) as (
	  -- returns the current list
	  select member_id
		from iam_group_member
	   where group_id = ?
	),
	keep_members (member_id) as (
	  -- returns the KEEP list
	  select member_id
		from current_members
	   where member_id in (select * from final_members)
	),
	delete_members (member_id) as (
	  -- returns the DELETE list
	  select member_id
		from current_members
	   where member_id not in (select * from final_members)
	),
	insert_members (member_id) as (
	  -- returns the ADD list
	  select member_id
		from final_members
	   where member_id not in (select * from keep_members)
	),
	final (action, member_id) as (
	  select 'delete', member_id
		from delete_members
	   union
	  select 'add', member_id
		from insert_members
	)
	select * from final
	order by action, member_id;
	`

	grantsBaseQuery = `
	with
	users (id) as (
	  select public_id
		from iam_user
	  %s -- anonUser || authUser
	),
	user_groups (id) as (
	  select group_id
		from iam_group_member_user
	   where member_id in (select id from users)
	),
	user_accounts (id) as (
	  select public_id
		from auth_account
	   where iam_user_id in (select id from users)
	),
	user_managed_groups (id) as (
	  select managed_group_id
		from auth_managed_group_member_account
	   where member_id in (select id from user_accounts)
	),
	managed_group_roles (role_id) as (
	  select role_id
		from iam_managed_group_role
	   where principal_id in (select id from user_managed_groups)
	),
	group_roles (role_id) as (
	  select role_id
		from iam_group_role
	   where principal_id in (select id from user_groups)
	),
	user_roles (role_id) as (
	  select role_id
		from iam_user_role
	   where principal_id in (select id from users)
	),
	user_group_roles (role_id) as (
	  select role_id
		from group_roles
	   union
	  select role_id
		from user_roles
	   union
	  select role_id
		from managed_group_roles
	),
	roles (role_id, role_scope_id, grant_scope_id) as (
		select
			iam_role.public_id,
			iam_role.scope_id,
			iam_role.grant_scope_id
		from iam_role
		where public_id in (select role_id from user_group_roles)
	),
	`

	grantsQuery = grantsBaseQuery + `
	final (role_id, role_scope, role_grant) as (
		select
			roles.role_id,
			roles.grant_scope_id,
			iam_role_grant.canonical_grant
		from roles
		inner join iam_role_grant
			on roles.role_id = iam_role_grant.role_id
			-- only retrieves roles with a grant! there can be roles that don't have grants (it's a valid state in boundary)
	)
	select role_id as role_id, role_scope as scope_id, role_grant as grant from final;
	`

	grantScopesQuery = grantsBaseQuery + `
	final (role_id, role_scope_id, grant_scope_id) as (
		select
			roles.role_id,
			roles.role_scope_id,
			iam_role_grant_scope.scope_id
		from roles
		inner join iam_role_grant_scope
			on roles.role_id = iam_role_grant_scope.role_id
	)
	select role_id as role_id, role_scope_id as role_scope_id, grant_scope_id as grant_scope_id from final;
	`

	grantsFromRolesQuery = `
	with
	roles (role_id) as (
		select public_id from iam_role where public_id in @role_ids
	),
	final (role_id, role_grant) as (
		select
			roles.role_id,
			iam_role_grant.canonical_grant
		from roles
		inner join iam_role_grant
			on roles.role_id = iam_role_grant.role_id
			-- only retrieves roles with a grant! there can be roles that don't have grants (it's a valid state in boundary)
	)
	select role_id as role_id, role_grant as grant from final;
	`

	estimateCountRoles = `
		select reltuples::bigint as estimate from pg_class where oid in ('iam_role'::regclass)
	`

	estimateCountUsers = `
		select reltuples::bigint as estimate from pg_class where oid in ('iam_user'::regclass)
	`

	estimateCountGroups = `
		select reltuples::bigint as estimate from pg_class where oid in ('iam_group'::regclass)
	`

	estimateCountScopes = `
		select reltuples::bigint as estimate from pg_class where oid in ('iam_scope'::regclass)
	`
)
