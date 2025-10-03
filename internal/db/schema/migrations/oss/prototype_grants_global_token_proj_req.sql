-- Non-Recursive request at global scope using global token with specific project scope
-- Lookup all permissions with grant scopes 'descendants', and 'individual' for the specific project

-- request scope: o__________10 (an org)
-- request resources: target, *, unknown
-- request token: at_global_children_per_org

-- omit all individually granted orgs and all permissioons with grant scope 'children' without individual grant to the specific project

select  app_token_permission_global.private_id as permission_id,
        app_token_permission_global.create_time,
        app_token_permission_global.grant_this_scope,
        app_token_permission_global.grant_scope,
        app_token_global.public_id as app_token_id,
        array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
        array_agg(distinct app_token_permission_global_individual_project_grant_scope.scope_id) as active_grant_scopes
from app_token_global
join app_token_permission_global
  on app_token_global.public_id = app_token_permission_global.app_token_id
  and app_token_global.public_id = 'at_global_descendants'
left join app_token_permission_global_individual_project_grant_scope
  on app_token_permission_global.private_id = app_token_permission_global_individual_project_grant_scope.permission_id
  and app_token_permission_global_individual_project_grant_scope.scope_id = 'p______o10_3'
join app_token_permission_grant
  on app_token_permission_global.private_id = app_token_permission_grant.permission_id
join iam_grant
  on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
  and iam_grant.resource in ('*', 'target', 'unknown')
where app_token_permission_global.grant_scope = 'descendants'
   or app_token_permission_global_individual_project_grant_scope.scope_id is not null
group by app_token_permission_global.private_id,
         app_token_permission_global.create_time,
         app_token_permission_global.grant_this_scope,
         app_token_permission_global.grant_scope,
         app_token_global.public_id;