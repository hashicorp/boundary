// Copyright IBM Corp. 2020, 2025
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

	resourceRoleGrantsForUsers = `
    with
    users (id) as (
      select public_id
        from iam_user
       where public_id = any(@user_ids)
    ),
    user_groups (id) as (
      select group_id
        from iam_group_member_user
       where member_id in (select id
                             from users)
    ),
    user_accounts (id) as (
      select public_id
        from auth_account
       where iam_user_id in (select id
                               from users)
    ),
    user_oidc_managed_groups (id) as (
      select managed_group_id
        from auth_oidc_managed_group_member_account
       where member_id in (select id
                             from user_accounts)
    ),
    user_ldap_managed_groups (id) as (
      select managed_group_id
        from auth_ldap_managed_group_member_account
       where member_id in (select id
                             from user_accounts)
    ),
    managed_group_roles (role_id) as (
      select distinct role_id
        from iam_managed_group_role
       where principal_id in (select id
                                from user_oidc_managed_groups)
          or principal_id in (select id
                                from user_ldap_managed_groups)
    ),
    group_roles (role_id) as (
      select role_id
        from iam_group_role
       where principal_id in (select id
                                from user_groups)
    ),
    user_roles (role_id) as (
      select role_id
        from iam_user_role
       where principal_id in (select id
                                from users)
    ),
    all_associated_roles (role_id) as (
      select role_id
        from group_roles
       union
      select role_id
        from user_roles
       union
      select role_id
        from managed_group_roles
    ),
    roles_with_grants (role_id, canonical_grant) as (
      select iam_role_grant.role_id,
             iam_role_grant.canonical_grant
        from iam_role_grant
        join iam_role
          on iam_role.public_id = iam_role_grant.role_id
        join iam_grant
          on iam_grant.canonical_grant = iam_role_grant.canonical_grant
       where iam_role.public_id in (select role_id
                                      from all_associated_roles)
         and iam_grant.resource = any(@resources)
    )`

	// grantsForUserGlobalResourcesQuery gets a user's grants for resources only applicable to global scopes.
	grantsForUserGlobalResourcesQuery = resourceRoleGrantsForUsers + `,
    global_roles_this_grant_scope as (
      select iam_role_global.public_id             as role_id,
             iam_role_global.scope_id              as role_scope_id,
             ''                                    as role_parent_scope_id,
             'individual'                          as grant_scope,
             iam_role_global.grant_this_role_scope as grant_this_role_scope,
             null                                  as individual_grant_scope, -- individual_grant_scopes are not applicable to global roles
             roles_with_grants.canonical_grant     as canonical_grant
        from iam_role_global
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_global.public_id
       where iam_role_global.grant_this_role_scope
    )
    select role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope,
           array_agg(distinct(individual_grant_scope)) filter (where individual_grant_scope is not null) as individual_grant_scopes,
           array_agg(distinct(canonical_grant))        as canonical_grants
      from global_roles_this_grant_scope
  group by role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope;
    `

	// grantsForUserOrgResourcesQuery gets a user's grants for resources only applicable to org scopes.
	grantsForUserOrgResourcesQuery = resourceRoleGrantsForUsers + `,
    global_roles_with_individual_or_special_grant_scopes as (
      select iam_role_global.public_id             as role_id,
             iam_role_global.scope_id              as role_scope_id,
             ''                                    as role_parent_scope_id,
             iam_role_global.grant_scope           as grant_scope,
             iam_role_global.grant_this_role_scope as grant_this_role_scope,
             individual.scope_id                   as individual_grant_scope,
             roles_with_grants.canonical_grant     as canonical_grant
        from iam_role_global
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_global.public_id
   left join iam_role_global_individual_org_grant_scope individual
          on individual.role_id = iam_role_global.public_id
       where iam_role_global.grant_scope = any('{ children, descendants }')
          or individual.scope_id = @request_scope_id
    ),
    org_roles_this_grant_scope as (
      select iam_role_org.public_id             as role_id,
             iam_role_org.scope_id              as role_scope_id,
             'global'                           as role_parent_scope_id,
             'individual'                       as grant_scope,
             iam_role_org.grant_this_role_scope as grant_this_role_scope,
             null                               as individual_grant_scope,
             roles_with_grants.canonical_grant  as canonical_grant
        from iam_role_org
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_org.public_id
       where iam_role_org.grant_this_role_scope
         and iam_role_org.scope_id = @request_scope_id
    ),
    global_and_org_roles as (
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from global_roles_with_individual_or_special_grant_scopes
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from org_roles_this_grant_scope
    )
    select role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope,
           array_agg(distinct(individual_grant_scope)) filter (where individual_grant_scope is not null) as individual_grant_scopes,
           array_agg(distinct(canonical_grant))        as canonical_grants
      from global_and_org_roles
  group by role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope;
    `

	// grantsForUserProjectResourcesQuery gets a user's grants for resources only applicable to project scopes.
	grantsForUserProjectResourcesQuery = resourceRoleGrantsForUsers + `,
    global_roles_with_individual_or_descendant_grant_scopes as (
      select iam_role_global.public_id             as role_id,
             iam_role_global.scope_id              as role_scope_id,
             ''                                    as role_parent_scope_id,
             iam_role_global.grant_scope           as grant_scope,
             iam_role_global.grant_this_role_scope as grant_this_role_scope,
             individual.scope_id                   as individual_grant_scope,
             roles_with_grants.canonical_grant     as canonical_grant
        from iam_role_global
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_global.public_id
   left join iam_role_global_individual_project_grant_scope individual
          on individual.role_id = iam_role_global.public_id
       where iam_role_global.grant_scope = 'descendants'
          or individual.scope_id = @request_scope_id
    ),
    org_roles_with_individual_or_children_grant_scopes as (
      select iam_role_org.public_id             as role_id,
             iam_role_org.scope_id              as role_scope_id,
             'global'                           as role_parent_scope_id,
             iam_role_org.grant_scope           as grant_scope,
             iam_role_org.grant_this_role_scope as grant_this_role_scope,
             individual.scope_id                as individual_grant_scope,
             roles_with_grants.canonical_grant  as canonical_grant
        from iam_role_org
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_org.public_id
        join iam_scope_project
          on iam_scope_project.parent_id = iam_role_org.scope_id
   left join iam_role_org_individual_grant_scope individual
          on individual.role_id = iam_role_org.public_id
       where individual.scope_id = @request_scope_id
          or (
             iam_role_org.grant_scope = 'children' and
             iam_scope_project.scope_id = @request_scope_id
          )
    ),
    project_roles_this_grant_scope as (
      select iam_role_project.public_id             as role_id,
             iam_role_project.scope_id              as role_scope_id,
             iam_scope_project.parent_id            as role_parent_scope_id,
             'individual'                           as grant_scope,
             iam_role_project.grant_this_role_scope as grant_this_role_scope,
             null                                   as individual_grant_scope,
             roles_with_grants.canonical_grant      as canonical_grant
        from iam_role_project
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_project.public_id
        join iam_scope_project
          on iam_scope_project.scope_id = iam_role_project.scope_id
       where iam_role_project.grant_this_role_scope
         and iam_role_project.scope_id = @request_scope_id
    ),
    all_roles as (
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from global_roles_with_individual_or_descendant_grant_scopes
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from org_roles_with_individual_or_children_grant_scopes
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from project_roles_this_grant_scope
    )
    select role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope,
           array_agg(distinct(individual_grant_scope)) filter (where individual_grant_scope is not null) as individual_grant_scopes,
           array_agg(distinct(canonical_grant))                                                          as canonical_grants
      from all_roles
  group by role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope;
    `

	// grantsForUserRecursiveQuery gets a user's grants for resources
	// applicable to all scopes at the global request scope.
	grantsForUserRecursiveQuery = resourceRoleGrantsForUsers + `,
    global_individual_grant_scopes (role_id, scope_id) as (
      select role_id, scope_id
        from iam_role_global_individual_org_grant_scope
       union
      select role_id, scope_id
        from iam_role_global_individual_project_grant_scope
    ),
    global_roles_this_grant_scope as (
      select iam_role_global.public_id             as role_id,
             iam_role_global.scope_id              as role_scope_id,
             ''                                    as role_parent_scope_id,
             iam_role_global.grant_scope           as grant_scope,
             iam_role_global.grant_this_role_scope as grant_this_role_scope,
             null                                  as individual_grant_scope,
             roles_with_grants.canonical_grant     as canonical_grant
        from iam_role_global
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_global.public_id
       where iam_role_global.grant_this_role_scope
    ),
    global_roles_with_special_grant_scopes as (
      select iam_role_global.public_id             as role_id,
             iam_role_global.scope_id              as role_scope_id,
             ''                                    as role_parent_scope_id,
             iam_role_global.grant_scope           as grant_scope,
             iam_role_global.grant_this_role_scope as grant_this_role_scope,
             null                                  as individual_grant_scope,
             roles_with_grants.canonical_grant     as canonical_grant
        from iam_role_global
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_global.public_id
       where iam_role_global.grant_scope = any('{ children, descendants }')
    ),
    global_roles_with_individual_grant_scopes as (
      select iam_role_global.public_id             as role_id,
             iam_role_global.scope_id              as role_scope_id,
             ''                                    as role_parent_scope_id,
             iam_role_global.grant_scope           as grant_scope,
             iam_role_global.grant_this_role_scope as grant_this_role_scope,
             individual.scope_id                   as individual_grant_scope,
             roles_with_grants.canonical_grant     as canonical_grant
        from iam_role_global
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_global.public_id
        join global_individual_grant_scopes individual
          on individual.role_id = iam_role_global.public_id
    ),
    org_roles_this_grant_scope as (
      select iam_role_org.public_id             as role_id,
             iam_role_org.scope_id              as role_scope_id,
             'global'                           as role_parent_scope_id,
             iam_role_org.grant_scope           as grant_scope,
             iam_role_org.grant_this_role_scope as grant_this_role_scope,
             null                               as individual_grant_scope,
             roles_with_grants.canonical_grant  as canonical_grant
        from iam_role_org
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_org.public_id
       where iam_role_org.grant_this_role_scope
    ),
    org_roles_with_children_grant_scopes as (
      select iam_role_org.public_id             as role_id,
             iam_role_org.scope_id              as role_scope_id,
             'global'                           as role_parent_scope_id,
             iam_role_org.grant_scope           as grant_scope,
             iam_role_org.grant_this_role_scope as grant_this_role_scope,
             null                               as individual_grant_scope,
             roles_with_grants.canonical_grant  as canonical_grant
        from iam_role_org
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_org.public_id
       where iam_role_org.grant_scope = 'children'
    ),
    org_roles_with_individual_grant_scopes as (
      select iam_role_org.public_id             as role_id,
             iam_role_org.scope_id              as role_scope_id,
             'global'                           as role_parent_scope_id,
             iam_role_org.grant_scope           as grant_scope,
             iam_role_org.grant_this_role_scope as grant_this_role_scope,
             individual.scope_id                as individual_grant_scope,
             roles_with_grants.canonical_grant  as canonical_grant
        from iam_role_org
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_org.public_id
        join iam_role_org_individual_grant_scope individual
          on individual.role_id = iam_role_org.public_id
    ),
    project_roles_this_grant_scope as (
      select iam_role_project.public_id             as role_id,
             iam_role_project.scope_id              as role_scope_id,
             iam_scope_project.parent_id            as role_parent_scope_id,
             'individual'                           as grant_scope,
             iam_role_project.grant_this_role_scope as grant_this_role_scope,
             null                                   as individual_grant_scope,
             roles_with_grants.canonical_grant      as canonical_grant
        from iam_role_project
        join roles_with_grants
          on roles_with_grants.role_id = iam_role_project.public_id
        join iam_scope_project
          on iam_scope_project.scope_id = iam_role_project.scope_id
       where iam_role_project.grant_this_role_scope
    ),
    all_roles as (
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from global_roles_this_grant_scope
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from global_roles_with_special_grant_scopes
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from global_roles_with_individual_grant_scopes
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from org_roles_this_grant_scope
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from org_roles_with_children_grant_scopes
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from org_roles_with_individual_grant_scopes
       union
      select role_id,
             role_scope_id,
             role_parent_scope_id,
             grant_scope,
             grant_this_role_scope,
             individual_grant_scope,
             canonical_grant
        from project_roles_this_grant_scope
    )
    select role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope,
           array_agg(distinct(individual_grant_scope)) filter (where individual_grant_scope is not null) as individual_grant_scopes,
           array_agg(distinct(canonical_grant))                                                          as canonical_grants
      from all_roles
  group by role_id,
           role_scope_id,
           role_parent_scope_id,
           grant_scope,
           grant_this_role_scope;
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

	scopeIdFromRoleIdQuery = `
	   select scope_id
		 from iam_role
		where public_id = @public_id;`

	listRolesQuery = `
with
combined_role_types (role_id) as (
    select public_id
      from iam_role
     where %s -- the where clause is programmatically generated
     order by create_time desc, public_id desc
     limit @limit
)
select public_id,
       scope_id,
       name,
       description,
       create_time,
       update_time,
       version
  from iam_role_global
 where public_id = any(select role_id from combined_role_types)
 union all
select public_id,
       scope_id,
       name,
       description,
       create_time,
       update_time,
       version
  from iam_role_org
 where public_id = any(select role_id from combined_role_types)
 union all
select public_id,
       scope_id,
       name,
       description,
       create_time,
       update_time,
       version
  from iam_role_project
 where public_id = any(select role_id from combined_role_types)
 order by update_time desc, public_id desc
`

	roleGrantsScopeQuery = `
with
global_roles (role_id) as (
  select public_id as role_id
    from iam_role_global
   where public_id = any($1)
),
org_roles (role_id) as (
  select public_id as role_id
    from iam_role_org
   where public_id = any($1)
),
proj_roles (role_id) as (
  select public_id as role_id
    from iam_role_project
   where public_id = any($1)
),
global_role_this_grants (role_id, scope_id_or_special, create_time) as (
  select public_id as role_id,
         'this' as scope_id_or_special,
         grant_this_role_scope_update_time as create_time
    from iam_role_global
   where public_id = any (select role_id from global_roles)
     and grant_this_role_scope = true
),
org_role_this_grants (role_id, scope_id_or_special, create_time) as (
  select public_id as role_id,
         'this' as scope_id_or_special,
         grant_this_role_scope_update_time as create_time
    from iam_role_org
   where public_id = any (select role_id from org_roles)
     and grant_this_role_scope = true
),
proj_role_this_grants (role_id, scope_id_or_special, create_time) as (
  select public_id as role_id,
         'this' as scope_id_or_special,
         create_time as create_time
    from iam_role_project
   where public_id = any (select role_id from proj_roles)
     and grant_this_role_scope = true
),
global_role_special_grants (role_id, scope_id_or_special, create_time) as (
  select public_id as role_id,
         grant_scope as scope_id_or_special,
         grant_this_role_scope_update_time as create_time
    from iam_role_global
   where public_id = any (select role_id from global_roles)
     and grant_scope != 'individual'
),
org_role_special_grants (role_id, scope_id_or_special, create_time) as (
  select public_id as role_id,
         grant_scope as scope_id_or_special,
         grant_this_role_scope_update_time as create_time
    from iam_role_org
   where public_id = any (select role_id from org_roles)
     and grant_scope != 'individual'
),
global_role_individual_org_grants (role_id, scope_id_or_special, create_time) as (
  select role_id as role_id,
         scope_id as scope_id_or_special,
         create_time as create_time
    from iam_role_global_individual_org_grant_scope
   where role_id = any (select role_id from global_roles)
),
global_role_individual_proj_grants (role_id, scope_id_or_special, create_time) as (
  select role_id as role_id,
         scope_id as scope_id_or_special,
         create_time as create_time
    from iam_role_global_individual_project_grant_scope
   where role_id = any (select role_id from global_roles)
),
org_role_individual_grants (role_id, scope_id_or_special, create_time) as (
  select role_id as role_id,
         scope_id as scope_id_or_special,
         create_time as create_time
    from iam_role_org_individual_grant_scope
   where role_id = any (select role_id from org_roles)
),
final (role_id, scope_id_or_special, create_time) as (
  select role_id, scope_id_or_special, create_time
    from global_role_this_grants
   union
  select role_id, scope_id_or_special, create_time
  	from org_role_this_grants
   union
  select role_id, scope_id_or_special, create_time
  	from proj_role_this_grants
   union
  select role_id, scope_id_or_special, create_time
  	from global_role_special_grants
   union
  select role_id, scope_id_or_special, create_time
  	from org_role_special_grants
   union
  select role_id, scope_id_or_special, create_time
  	from global_role_individual_org_grants
   union
  select role_id, scope_id_or_special, create_time
  	from global_role_individual_proj_grants
   union
  select role_id, scope_id_or_special, create_time
  	from org_role_individual_grants
)
select role_id,
       scope_id_or_special,
       create_time
  from final;
`
)
