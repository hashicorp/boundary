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
   select app_token_permission_global.private_id                                           as permission_id,
          app_token_permission_global.description,
          app_token_permission_global.create_time,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id                                                       as app_token_id,
          array_agg(distinct app_token_permission_grant.canonical_grant)                   as canonical_grants,
          array_agg(distinct coalesce(iam_scope_org.scope_id, iam_scope_project.scope_id)) as active_grant_scopes
     from app_token_global
     join app_token_permission_global
       on app_token_global.public_id = app_token_permission_global.app_token_id
      and app_token_global.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_global.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
left join app_token_permission_global_individual_org_grant_scope
       on app_token_permission_global.private_id = app_token_permission_global_individual_org_grant_scope.permission_id
left join iam_scope_org
       on app_token_permission_global_individual_org_grant_scope.scope_id = iam_scope_org.scope_id
left join app_token_permission_global_individual_project_grant_scope
       on app_token_permission_global.private_id = app_token_permission_global_individual_project_grant_scope.permission_id
left join iam_scope_project
       on app_token_permission_global_individual_project_grant_scope.scope_id = iam_scope_project.scope_id
 group by app_token_permission_global.private_id,
          app_token_permission_global.description,
          app_token_permission_global.create_time,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id;
    `

	// grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery gets a global app token's grants for resources
	// applicable to global and org scopes.
	grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery = `
  select  app_token_permission_global.private_id                         as permission_id,
          app_token_permission_global.description,
          app_token_permission_global.create_time,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id                                     as app_token_id,
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
left join app_token_permission_global_individual_org_grant_scope org_grants
       on app_token_permission_global.private_id = org_grants.permission_id
left join iam_scope_org
       on org_grants.scope_id = iam_scope_org.scope_id
 group by app_token_permission_global.private_id,
          app_token_permission_global.description,
          app_token_permission_global.create_time,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id;
    `

	// grantsForGlobalTokenProjectResourcesRecursiveQuery gets a global app token's grants for resources
	// applicable to the project scope.
	grantsForGlobalTokenProjectResourcesRecursiveQuery = `
   select app_token_permission_global.private_id                         as permission_id,
          app_token_permission_global.description,
          app_token_permission_global.create_time,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id                                     as app_token_id,
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
left join app_token_permission_global_individual_project_grant_scope proj_grants
       on app_token_permission_global.private_id = proj_grants.permission_id
left join iam_scope_project
       on proj_grants.scope_id = iam_scope_project.scope_id
left join app_token_permission_global_individual_org_grant_scope org_grants
       on app_token_permission_global.private_id = org_grants.permission_id
    where org_grants.permission_id is null
       or (
          app_token_permission_global.grant_scope = 'children' and
          proj_grants.scope_id is not null
       )
 group by app_token_permission_global.private_id,
          app_token_permission_global.description,
          app_token_permission_global.create_time,
          app_token_permission_global.grant_this_scope,
          app_token_permission_global.grant_scope,
          app_token_global.public_id;
    `

	// grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery gets an org app token's grants for resources
	// applicable to all scopes.
	grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery = `
   select app_token_permission_org.private_id                            as permission_id,
          app_token_permission_org.description,
          app_token_permission_org.create_time,
          app_token_permission_org.grant_this_scope,
          app_token_permission_org.grant_scope,
          app_token_org.public_id                                        as app_token_id,
          array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
          array_agg(distinct coalesce(iam_scope_project.scope_id))       as active_grant_scopes
     from app_token_org
     join app_token_permission_org
       on app_token_org.public_id = app_token_permission_org.app_token_id
      and app_token_org.public_id = any(@app_token_ids)
     join app_token_permission_grant
       on app_token_permission_org.private_id = app_token_permission_grant.permission_id
     join iam_grant
       on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
      and iam_grant.resource = any(@resources)
left join app_token_permission_org_individual_grant_scope individual_project_grants
       on app_token_permission_org.private_id = individual_project_grants.permission_id
left join iam_scope_project
       on individual_project_grants.scope_id = iam_scope_project.scope_id
 group by app_token_permission_org.private_id,
          app_token_permission_org.description,
          app_token_permission_org.create_time,
          app_token_permission_org.grant_this_scope,
          app_token_permission_org.grant_scope,
          app_token_org.public_id;
    `
)
