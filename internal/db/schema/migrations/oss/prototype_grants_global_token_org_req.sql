-- Non-Recursive request at global scope using global token with specific org scope
-- Lookup all permissions with grant scopes 'children' and 'individual' for the specific org
-- request scope: o__________10 (an org)
-- request resources: user, *, unknown
-- request token: at_global_comprehensive

select  app_token_permission_global.private_id as permission_id,
        app_token_permission_global.create_time,
        app_token_permission_global.grant_this_scope,
        app_token_permission_global.grant_scope,
        app_token_global.public_id as app_token_id,
        array_agg(distinct app_token_permission_grant.canonical_grant) as canonical_grants,
        array_agg(distinct app_token_permission_global_individual_org_grant_scope.scope_id) as active_grant_scopes
from app_token_global
join app_token_permission_global
  on app_token_global.public_id = app_token_permission_global.app_token_id
  and app_token_global.public_id = 'at_global_comprehensive'
join app_token_permission_grant
  on app_token_permission_global.private_id = app_token_permission_grant.permission_id
join iam_grant
  on app_token_permission_grant.canonical_grant = iam_grant.canonical_grant
  and iam_grant.resource in ('*', 'user', 'unknown')
left join app_token_permission_global_individual_org_grant_scope
  on app_token_permission_global.private_id = app_token_permission_global_individual_org_grant_scope.permission_id
  and app_token_permission_global_individual_org_grant_scope.scope_id = 'o__________10'
where app_token_permission_global.grant_scope != 'individual'
   or (app_token_permission_global.grant_scope = 'individual' 
       and app_token_permission_global_individual_org_grant_scope.scope_id is not null)
group by app_token_permission_global.private_id,
         app_token_permission_global.create_time,
         app_token_permission_global.grant_this_scope,
         app_token_permission_global.grant_scope,
         app_token_global.public_id;