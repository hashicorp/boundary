-- this query returns all grants and grant scopes of a global token with global&org&project resources (e.g. Policies)
-- all grant scopes recursively (global -> org -> project) 

-- Optimized version with better CTE structure
with token_permissions as (
  select app_token_permission_global.private_id,
         app_token_permission_global.description,
         app_token_permission_global.create_time,
         app_token_permission_global.grant_this_scope,
         app_token_permission_global.grant_scope,
         app_token_global.public_id as app_token_id
    from app_token_global
    join app_token_permission_global
      on app_token_global.public_id = app_token_permission_global.app_token_id
   where app_token_global.public_id = 'at_global_comprehensive'
     and app_token_permission_global.grant_this_scope -- only need 
)
select  token_permissions.private_id as permission_id,
        token_permissions.description,
        token_permissions.create_time,
        token_permissions.grant_this_scope,
        token_permissions.grant_scope,
        token_permissions.app_token_id,
        '{}'::text[] as active_grant_scopes
     from token_permissions token_permissions
 group by token_permissions.private_id,
          token_permissions.description,
          token_permissions.create_time,
          token_permissions.grant_this_scope,
          token_permissions.grant_scope,
          token_permissions.app_token_id;