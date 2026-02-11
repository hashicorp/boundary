// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

// query.go contains "raw sql" for the apptoken package that goes directly against
// the db via sql.DB vs the standard pattern of using the internal/db package to
// interact with the db.
const (
	// grantsForGlobalTokenGlobalOrgProjectResourcesRecursiveQuery gets a global app token's grants for resources
	// applicable to all scopes.
	grantsForGlobalTokenGlobalOrgProjectResourcesRecursiveQuery = `
   select app_token_permission_global.private_id                                                       as permission_id,
          app_token_permission_global.description,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id                                                                   as app_token_id,
          ''                                                                                           as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant)                               as canonical_grants,
          array_agg(distinct coalesce(iam_scope_org.scope_id, iam_scope_project.scope_id))
            filter (where    coalesce(iam_scope_org.scope_id, iam_scope_project.scope_id) is not null) as active_grant_scopes
     from app_token_global
     join app_token_permission_global
       on app_token_global.public_id = app_token_permission_global.app_token_id
      and app_token_global.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_global.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
left join app_token_permission_global_individual_org_grant_scope org_grant_scope
       on app_token_permission_global.private_id = org_grant_scope.permission_id
left join iam_scope_org
       on org_grant_scope.scope_id = iam_scope_org.scope_id
left join app_token_permission_global_individual_project_grant_scope project_grant_scope
       on app_token_permission_global.private_id = project_grant_scope.permission_id
left join iam_scope_project
       on project_grant_scope.scope_id = iam_scope_project.scope_id
 group by app_token_permission_global.private_id,
          app_token_global.public_id;
    `

	// grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery gets a global app token's grants for resources
	// applicable to global and org scopes.
	grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery = `
   select app_token_permission_global.private_id                         as permission_id,
          app_token_permission_global.description,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id                                     as app_token_id,
          ''                                                             as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(distinct iam_scope_org.scope_id)                     as active_grant_scopes
     from app_token_global
     join app_token_permission_global
       on app_token_global.public_id = app_token_permission_global.app_token_id
      and app_token_global.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_global.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
left join app_token_permission_global_individual_org_grant_scope org_grant_scope
       on app_token_permission_global.private_id = org_grant_scope.permission_id
left join iam_scope_org
       on org_grant_scope.scope_id = iam_scope_org.scope_id
 group by app_token_permission_global.private_id,
          app_token_global.public_id;
    `

	// grantsForGlobalTokenProjectResourcesRecursiveQuery gets a global app token's grants for resources
	// applicable to the project scope.
	grantsForGlobalTokenProjectResourcesRecursiveQuery = `
   select app_token_permission_global.private_id                         as permission_id,
          app_token_permission_global.description,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id                                     as app_token_id,
          ''                                                             as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(distinct iam_scope_project.scope_id)                 as active_grant_scopes
     from app_token_global
     join app_token_permission_global
       on app_token_global.public_id = app_token_permission_global.app_token_id
      and app_token_global.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_global.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
left join app_token_permission_global_individual_project_grant_scope project_grant_scope
       on app_token_permission_global.private_id = project_grant_scope.permission_id
left join iam_scope_project
       on project_grant_scope.scope_id = iam_scope_project.scope_id
    where app_token_permission_global.grant_scope = 'descendants'
       or project_grant_scope.scope_id is not null
 group by app_token_permission_global.private_id,
          app_token_global.public_id;
    `

	// grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery gets an org app token's grants for resources
	// applicable to all scopes.
	grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery = `
   select app_token_permission_org.private_id                            as permission_id,
          app_token_permission_org.description,
          app_token_permission_org.grant_this_scope,
          app_token_permission_org.grant_scope,
          app_token_org.public_id                                        as app_token_id,
          'global'                                                       as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(distinct iam_scope_project.scope_id)                 as active_grant_scopes
     from app_token_org
     join app_token_permission_org
       on app_token_org.public_id = app_token_permission_org.app_token_id
      and app_token_org.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_org.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
left join app_token_permission_org_individual_grant_scope project_grant_scope
       on app_token_permission_org.private_id = project_grant_scope.permission_id
left join iam_scope_project
       on project_grant_scope.scope_id = iam_scope_project.scope_id
 group by app_token_permission_org.private_id,
          app_token_org.public_id;
    `

	// grantsForOrgTokenGlobalOrgResourcesRecursiveQuery gets an org app token's grants for resources
	// applicable to global and org scopes.
	grantsForOrgTokenGlobalOrgResourcesRecursiveQuery = `
   select app_token_permission_org.private_id                            as permission_id,
          app_token_permission_org.description,
          app_token_permission_org.grant_this_scope,
          app_token_permission_org.grant_scope,
          app_token_org.public_id                                        as app_token_id,
          'global'                                                       as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(distinct app_token_org.scope_id)                     as active_grant_scopes
     from app_token_org
     join app_token_permission_org
       on app_token_org.public_id = app_token_permission_org.app_token_id
      and app_token_org.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_org.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
    where app_token_permission_org.grant_this_scope = true
 group by app_token_permission_org.private_id,
          app_token_org.public_id;
    `

	// grantsForOrgTokenProjectResourcesRecursiveQuery gets an org app token's grants for resources
	// applicable to any project scope.
	grantsForOrgTokenProjectResourcesRecursiveQuery = `
   select app_token_permission_org.private_id                            as permission_id,
          app_token_permission_org.description,
          app_token_permission_org.grant_this_scope,
          app_token_permission_org.grant_scope,
          app_token_org.public_id                                        as app_token_id,
          'global'                                                       as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(distinct iam_scope_project.scope_id)                 as active_grant_scopes
     from app_token_org
     join app_token_permission_org
       on app_token_org.public_id = app_token_permission_org.app_token_id
      and app_token_org.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_org.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
left join app_token_permission_org_individual_grant_scope project_grant_scope
       on app_token_permission_org.private_id = project_grant_scope.permission_id
left join iam_scope_project
       on project_grant_scope.scope_id = iam_scope_project.scope_id
    where app_token_permission_org.grant_scope = 'children'
       or project_grant_scope.scope_id is not null
 group by app_token_permission_org.private_id,
          app_token_org.public_id;
    `

	// grantsForProjectTokenRecursiveQuery gets a project app token's grants for resources
	// applicable to any project scope.
	grantsForProjectTokenRecursiveQuery = `
   select app_token_permission_project.private_id                        as permission_id,
          app_token_permission_project.description,
          app_token_permission_project.grant_this_scope,
          'individual'                                                   as grant_scope,
          app_token_project.public_id                                    as app_token_id,
          iam_scope_project.parent_id                                    as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(iam_scope_project.scope_id)                          as active_grant_scopes
     from app_token_project
     join iam_scope_project
       on iam_scope_project.scope_id = app_token_project.scope_id
     join app_token_permission_project
       on app_token_project.public_id = app_token_permission_project.app_token_id
      and app_token_project.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_project.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
    where app_token_permission_project.grant_this_scope = true
 group by app_token_permission_project.private_id,
          app_token_project.public_id,
          iam_scope_project.parent_id;
    `

	// grantsForProjectTokenQuery gets a project app token's grants for resources
	// applicable to a project request scope.
	grantsForProjectTokenQuery = `
   select app_token_permission_project.private_id                        as permission_id,
          app_token_permission_project.description,
          app_token_permission_project.grant_this_scope,
          'individual'                                                   as grant_scope,
          app_token_project.public_id                                    as app_token_id,
          iam_scope_project.parent_id                                    as app_token_parent_scope_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(iam_scope_project.scope_id)                          as active_grant_scopes
     from app_token_project
     join iam_scope_project
       on iam_scope_project.scope_id = app_token_project.scope_id
      and iam_scope_project.scope_id = @request_scope_id
     join app_token_permission_project
       on app_token_project.public_id = app_token_permission_project.app_token_id
      and app_token_project.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_project.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
    where app_token_permission_project.grant_this_scope = true
 group by app_token_permission_project.private_id,
          app_token_project.public_id,
          iam_scope_project.parent_id;
    `

	// grantsForGlobalTokenGlobalRequestScopeQuery gets a global app token's grants for resources
	// applicable to the global request scope.
	grantsForGlobalTokenGlobalRequestScopeQuery = `
      select app_token_permission_global.private_id                         as permission_id,
             app_token_permission_global.description,
             app_token_permission_global.grant_this_scope,
             app_token_permission_global.grant_scope,
             app_token_global.public_id                                     as app_token_id,
             ''                                                             as app_token_parent_scope_id,
             array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
             null                                                           as active_grant_scopes
        from app_token_global
        join app_token_permission_global
          on app_token_global.public_id = app_token_permission_global.app_token_id
         and app_token_global.public_id = any(@app_token_ids)
        join app_token_permission_grant
          on app_token_permission_global.private_id = app_token_permission_grant.permission_id
        join iam_grant
          on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
         and iam_grant.resource = any(@resources)
       where app_token_permission_global.grant_this_scope
    group by app_token_permission_global.private_id,
             app_token_global.public_id;
    `

	// grantsForGlobalTokenOrgRequestScopeQuery gets a global app token's grants for resources
	// applicable to org request scopes.
	grantsForGlobalTokenOrgRequestScopeQuery = `
      select app_token_permission_global.private_id                                                            as permission_id,
             app_token_permission_global.description,
             app_token_permission_global.grant_this_scope,
             app_token_permission_global.grant_scope,
             app_token_global.public_id                                                                        as app_token_id,
             ''                                                                                                as app_token_parent_scope_id,
             array_agg(distinct app_token_permission_grant.canonical_grant)                                    as canonical_grants,
             array_agg(distinct(org_grant_scope.scope_id)) filter (where org_grant_scope.scope_id is not null) as active_grant_scopes
        from app_token_global
        join app_token_permission_global
          on app_token_global.public_id = app_token_permission_global.app_token_id
         and app_token_global.public_id = any(@app_token_ids)
        join app_token_permission_grant
          on app_token_permission_global.private_id = app_token_permission_grant.permission_id
        join iam_grant
          on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
         and iam_grant.resource = any(@resources)
        left join app_token_permission_global_individual_org_grant_scope org_grant_scope
          on app_token_permission_global.private_id = org_grant_scope.permission_id
         and org_grant_scope.scope_id = @request_scope_id
       where app_token_permission_global.grant_scope != 'individual'
          or org_grant_scope.scope_id is not null
    group by app_token_permission_global.private_id,
             app_token_global.public_id;
    `

	// grantsForGlobalTokenProjectRequestScopeQuery gets a global app token's grants for resources
	// applicable to project request scopes.
	grantsForGlobalTokenProjectRequestScopeQuery = `
      select app_token_permission_global.private_id                                                                    as permission_id,
             app_token_permission_global.description,
             app_token_permission_global.grant_this_scope,
             app_token_permission_global.grant_scope,
             app_token_global.public_id                                                                                as app_token_id,
             ''                                                                                                        as app_token_parent_scope_id,
             array_agg(distinct app_token_permission_grant.canonical_grant)                                            as canonical_grants,
             array_agg(distinct(project_grant_scope.scope_id)) filter (where project_grant_scope.scope_id is not null) as active_grant_scopes
        from app_token_global
        join app_token_permission_global
          on app_token_global.public_id = app_token_permission_global.app_token_id
         and app_token_global.public_id = any(@app_token_ids)
        join app_token_permission_grant
          on app_token_permission_global.private_id = app_token_permission_grant.permission_id
        join iam_grant
          on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
         and iam_grant.resource = any(@resources)
        left join app_token_permission_global_individual_project_grant_scope project_grant_scope
          on app_token_permission_global.private_id = project_grant_scope.permission_id
         and project_grant_scope.scope_id = @request_scope_id
       where app_token_permission_global.grant_scope = 'descendants'
          or project_grant_scope.scope_id is not null
    group by app_token_permission_global.private_id,
             app_token_global.public_id;
    `

	// grantsForOrgTokenOrgRequestScopeQuery gets an org app token's grants for resources
	// applicable to an org request scope.
	grantsForOrgTokenOrgRequestScopeQuery = `
      select app_token_permission_org.private_id                            as permission_id,
             app_token_permission_org.description,
             app_token_permission_org.grant_this_scope,
             app_token_permission_org.grant_scope,
             app_token_org.public_id                                        as app_token_id,
             'global'                                                       as app_token_parent_scope_id,
             array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
             array_agg(app_token_org.scope_id)                              as active_grant_scopes
        from app_token_org
        join app_token_permission_org
          on app_token_org.public_id = app_token_permission_org.app_token_id
         and app_token_org.public_id = any(@app_token_ids)
         and app_token_org.scope_id  = @request_scope_id
        join app_token_permission_grant
          on app_token_permission_org.private_id = app_token_permission_grant.permission_id
        join iam_grant
          on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
         and iam_grant.resource = any(@resources)
       where app_token_permission_org.grant_this_scope
    group by app_token_permission_org.private_id,
             app_token_org.public_id;
    `

	// grantsForOrgTokenProjectRequestScopeQuery gets an org app token's grants for resources
	// applicable to a project request scope.
	grantsForOrgTokenProjectRequestScopeQuery = `
      select app_token_permission_org.private_id                                                                       as permission_id,
             app_token_permission_org.description,
             app_token_permission_org.grant_this_scope,
             app_token_permission_org.grant_scope,
             app_token_org.public_id                                                                                   as app_token_id,
             'global'                                                                                                  as app_token_parent_scope_id,
             array_agg(distinct app_token_permission_grant.canonical_grant)                                            as canonical_grants,
             array_agg(distinct(project_grant_scope.scope_id)) filter (where project_grant_scope.scope_id is not null) as active_grant_scopes
        from app_token_org
        join app_token_permission_org
          on app_token_org.public_id = app_token_permission_org.app_token_id
         and app_token_org.public_id = any(@app_token_ids)
        join app_token_permission_grant
          on app_token_permission_org.private_id = app_token_permission_grant.permission_id
        join iam_grant
          on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
         and iam_grant.resource = any(@resources)
        join iam_scope_project
          on iam_scope_project.parent_id = app_token_org.scope_id
   left join app_token_permission_org_individual_grant_scope project_grant_scope
          on app_token_permission_org.private_id = project_grant_scope.permission_id
       where project_grant_scope.scope_id = @request_scope_id
          or (
             app_token_permission_org.grant_scope = 'children' and
             iam_scope_project.scope_id = @request_scope_id
          )
    group by app_token_permission_org.private_id,
             app_token_org.public_id;
    `

	// estimateCountAppTokens estimates the total number of app tokens in the three app token tables
	estimateCountAppTokens = `
   select sum(reltuples::bigint) as estimate 
     from pg_class 
    where oid in ('app_token_global'::regclass, 'app_token_org'::regclass, 'app_token_project'::regclass)
`

	scopeIdFromAppTokenIdQuery = `
    select scope_id
      from app_token
     where public_id = @public_id;`
)
