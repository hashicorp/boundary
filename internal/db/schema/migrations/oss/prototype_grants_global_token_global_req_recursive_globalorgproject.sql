-- Recursive request at global scope
-- Lookup all permissions with grant scopes 'descendants', 'children', and 'individual' for orgs and projects

-- request scope: global
-- request resources: role, *, unknown
-- request token: at_global_children_per_org

with filtered_permissions as (
  -- Get permissions filtered by resource type
  select distinct app_token_permission_global.private_id,
         app_token_permission_global.description,
         app_token_permission_global.create_time,
         app_token_permission_global.grant_this_scope,
         app_token_permission_global.grant_scope,
         app_token_global.public_id,
         array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants
  from app_token_global
  join app_token_permission_global
    on app_token_global.public_id = app_token_permission_global.app_token_id
  join app_token_permission_grant
    on app_token_permission_global.private_id = app_token_permission_grant.permission_id
  join iam_grant
    on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
  join iam_grant_resource_enm
    on iam_grant.resource = iam_grant_resource_enm.name
  where iam_grant_resource_enm.name in ('*', 'role', 'unknown')
    and app_token_global.public_id = 'at_global_comprehensive'
  group by app_token_permission_global.private_id,
           app_token_permission_global.description,
           app_token_permission_global.create_time,
           app_token_permission_global.grant_this_scope,
           app_token_permission_global.grant_scope,
           app_token_global.public_id
),
individual_grant_scopes as (
  -- Union of individual grant scope types, filtered by permissions with correct resource enm
  select filtered_permissions.private_id,
         filtered_permissions.description,
         filtered_permissions.create_time,
         filtered_permissions.grant_this_scope,
         filtered_permissions.grant_scope,
         filtered_permissions.public_id,
         filtered_permissions.canonical_grants,
         iam_scope_org.scope_id as scope_id
  from app_token_permission_global_individual_org_grant_scope org_grants
  join filtered_permissions
    on org_grants.permission_id = filtered_permissions.private_id
  join iam_scope_org
    on org_grants.scope_id = iam_scope_org.scope_id
  union all
  select filtered_permissions.private_id,
         filtered_permissions.description,
         filtered_permissions.create_time,
         filtered_permissions.grant_this_scope,
         filtered_permissions.grant_scope,
         filtered_permissions.public_id,
         filtered_permissions.canonical_grants,
         iam_scope_project.scope_id as scope_id
  from app_token_permission_global_individual_project_grant_scope project_grants
  join filtered_permissions
    on project_grants.permission_id = filtered_permissions.private_id
  join iam_scope_project
    on project_grants.scope_id = iam_scope_project.scope_id
)
select  individual_grant_scopes.private_id as permission_id,
        individual_grant_scopes.description,
        individual_grant_scopes.create_time,
        individual_grant_scopes.grant_this_scope,
        individual_grant_scopes.grant_scope,
        individual_grant_scopes.public_id as app_token_id,
        individual_grant_scopes.canonical_grants,
        array_agg(distinct individual_grant_scopes.scope_id) as active_grant_scopes
from individual_grant_scopes
group by individual_grant_scopes.private_id,
         individual_grant_scopes.description,
         individual_grant_scopes.create_time,
         individual_grant_scopes.grant_this_scope,
         individual_grant_scopes.grant_scope,
         individual_grant_scopes.public_id,
         individual_grant_scopes.canonical_grants