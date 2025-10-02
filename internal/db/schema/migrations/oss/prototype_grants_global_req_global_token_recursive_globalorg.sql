-- Recursive request at global scope using global token with global&org resources (e.g. Policies, Users)
-- Lookup all permissions with grant scopes 'descendants', 'children', and 'individual' for orgs
select  app_token_permission_global.private_id as permission_id,
        app_token_permission_global.description,
        app_token_permission_global.create_time,
        app_token_permission_global.grant_this_scope,
        app_token_permission_global.grant_scope,
        app_token_global.public_id as app_token_id,
        array_agg(distinct iam_scope.public_id) as active_grant_scopes
from app_token_global
join app_token_permission_global
  on app_token_global.public_id = app_token_permission_global.app_token_id
join app_token_permission_grant
  on app_token_permission_global.private_id = app_token_permission_grant.permission_id
join iam_grant
  on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
join iam_grant_resource_enm
  on iam_grant.resource = iam_grant_resource_enm.name
join app_token_permission_global_individual_org_grant_scope org_grants
  on app_token_permission_global.private_id = org_grants.permission_id
join iam_scope
  on org_grants.scope_id = iam_scope.public_id
where iam_grant_resource_enm.name in ('*', 'user', 'unknown')
  and app_token_global.public_id = 'at_global_comprehensive'
group by app_token_permission_global.private_id,
         app_token_permission_global.description,
         app_token_permission_global.create_time,
         app_token_permission_global.grant_this_scope,
         app_token_permission_global.grant_scope,
         app_token_global.public_id;