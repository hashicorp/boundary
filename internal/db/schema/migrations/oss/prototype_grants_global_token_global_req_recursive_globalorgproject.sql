-- Recursive request at global scope - OPTIMIZED
-- Lookup all permissions with grant scopes 'descendants', 'children', and 'individual' for orgs and projects
-- Optimized version with CTE to pre-filter relevant permission IDs

-- request scope: global
-- request resources: role, *, unknown  
-- request token: at_global_comprehensive

select  app_token_permission_global.private_id as permission_id,
        app_token_permission_global.description,
        app_token_permission_global.create_time,
        app_token_permission_global.grant_this_scope,
        app_token_permission_global.grant_scope,
        app_token_global.public_id as app_token_id,
        array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
        array_agg(distinct coalesce(iam_scope_org.scope_id, iam_scope_project.scope_id))  as active_grant_scopes
from app_token_global
join app_token_permission_global
  on app_token_global.public_id = app_token_permission_global.app_token_id
  and app_token_global.public_id = 'at_global_comprehensive'
join app_token_permission_grant
  on app_token_permission_global.private_id = app_token_permission_grant.permission_id
join iam_grant
  on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
  and iam_grant.resource in ('*', 'role', 'unknown')
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