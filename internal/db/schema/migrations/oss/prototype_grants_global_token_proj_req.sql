-- Non-Recursive request at global scope using global token with specific project scope
-- Lookup all permissions with grant scopes 'descendants', and 'individual' for the specific project

-- request scope: o__________10 (an org)
-- request resources: target, *, unknown
-- request token: at_global_children_per_org

with filtered_permissions as (
  select distinct app_token_permission_global.private_id,
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
   where iam_grant_resource_enm.name in ('*', 'target', 'unknown')
     and app_token_global.public_id = 'at_global_children_per_org'
   group by app_token_permission_global.private_id,
            app_token_permission_global.create_time,
            app_token_permission_global.grant_this_scope,
            app_token_permission_global.grant_scope,
            app_token_global.public_id
),
individual_org_grant_scopes as (
  -- Org individual grant scopes, filtered by permissions and req scope hierarchy
  select app_token_permission_global_individual_project_grant_scope.permission_id,
         app_token_permission_global_individual_project_grant_scope.scope_id
    from app_token_permission_global_individual_project_grant_scope
    join filtered_permissions
      on app_token_permission_global_individual_project_grant_scope.permission_id = filtered_permissions.private_id
   where app_token_permission_global_individual_project_grant_scope.scope_id = 'p______o10_3'
),
all_grant_scopes as (
  -- Combine filtered permissions with their individual grant scopes, include permissions without individual scopes
  select filtered_permissions.private_id,
         filtered_permissions.create_time,
         filtered_permissions.grant_this_scope,
         filtered_permissions.grant_scope,
         filtered_permissions.public_id,
         filtered_permissions.canonical_grants,
         individual_org_grant_scopes.scope_id
  from filtered_permissions
  left join individual_org_grant_scopes
    on filtered_permissions.private_id = individual_org_grant_scopes.permission_id
)
select  all_grant_scopes.private_id as permission_id,
        all_grant_scopes.create_time,
        all_grant_scopes.grant_this_scope,
        all_grant_scopes.grant_scope,
        all_grant_scopes.public_id as app_token_id,
        all_grant_scopes.canonical_grants,
        array_agg(distinct all_grant_scopes.scope_id) as active_grant_scopes
  from all_grant_scopes
 where all_grant_scopes.grant_scope in ('descendants', 'individual')
    or all_grant_scopes.scope_id is not null
group by all_grant_scopes.private_id,
         all_grant_scopes.create_time,
         all_grant_scopes.grant_this_scope,
         all_grant_scopes.grant_scope,
         all_grant_scopes.public_id,
         all_grant_scopes.canonical_grants