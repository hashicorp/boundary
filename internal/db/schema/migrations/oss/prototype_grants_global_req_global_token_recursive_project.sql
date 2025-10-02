-- Recursive request at global scope using global token with project resources (e.g. Targets)
-- Lookup all permissions with grant scopes 'descendants', and 'individual' for projects

with filtered_permissions as (
  -- Get permissions filtered by resource type
  select distinct app_token_permission_global.private_id,
         app_token_permission_global.description,
         app_token_permission_global.create_time,
         app_token_permission_global.grant_this_scope,
         app_token_permission_global.grant_scope,
         app_token_global.public_id
  from app_token_global
  join app_token_permission_global
    on app_token_global.public_id = app_token_permission_global.app_token_id
  join app_token_permission_grant
    on app_token_permission_global.private_id = app_token_permission_grant.permission_id
  join iam_grant
    on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
  join iam_grant_resource_enm
    on iam_grant.resource = iam_grant_resource_enm.name
  where iam_grant_resource_enm.name in ('*', 'target', 'unknown')
    and app_token_global.public_id = 'at_global_comprehensive'
),
individual_grant_scopes as (
  -- Union of individual grant scope types, filtered by permissions with correct resource enm
  select org_grants.permission_id, org_grants.scope_id
  from app_token_permission_global_individual_org_grant_scope org_grants
  join filtered_permissions
    on org_grants.permission_id = filtered_permissions.private_id
  union all
  select project_grants.permission_id, project_grants.scope_id
  from app_token_permission_global_individual_project_grant_scope project_grants
  join filtered_permissions
    on project_grants.permission_id = filtered_permissions.private_id
),
all_grant_scopes as (
  -- Combine filtered permissions with their individual grant scopes
  select filtered_permissions.private_id,
         filtered_permissions.description,
         filtered_permissions.create_time,
         filtered_permissions.grant_this_scope,
         filtered_permissions.grant_scope,
         filtered_permissions.public_id,
         individual_grant_scopes.scope_id
  from filtered_permissions
  join individual_grant_scopes
    on filtered_permissions.private_id = individual_grant_scopes.permission_id
)
select  all_grant_scopes.private_id as permission_id,
        all_grant_scopes.description,
        all_grant_scopes.create_time,
        all_grant_scopes.grant_this_scope,
        all_grant_scopes.grant_scope,
        all_grant_scopes.public_id as app_token_id,
        array_agg(distinct iam_scope.public_id) as active_grant_scopes
from all_grant_scopes
join iam_scope
  on all_grant_scopes.scope_id = iam_scope.public_id
group by all_grant_scopes.private_id,
         all_grant_scopes.description,
         all_grant_scopes.create_time,
         all_grant_scopes.grant_this_scope,
         all_grant_scopes.grant_scope,
         all_grant_scopes.public_id