-- Get Global 
-- Query to get app token permissions with scope existence and delete times

-- delete a scopoe to test 
-- delete from iam_scope where public_id = 'o__________14';

select app_token_permission_global.private_id       as permission_id,
       app_token_permission_global.description      as description,
       app_token_permission_global.create_time      as create_time,
       app_token_permission_global.grant_this_scope as grant_this_scope,
       app_token_permission_global.grant_scope      as grant_scope,
       app_token_global.public_id                   as app_token_id,
       array_agg(distinct coalesce(org_grants.scope_id, project_grants.scope_id)) 
         filter (where (org_grants.scope_id is not null and org_scope.public_id is not null)
                    or (project_grants.scope_id is not null and project_scope.public_id is not null))
         as active_grant_scope_ids,
       array_agg(distinct coalesce(org_grants.scope_id, project_grants.scope_id)) 
         filter (where (org_grants.scope_id is not null and org_scope.public_id is null)
                    or (project_grants.scope_id is not null and project_scope.public_id is null))
         as deleted_grant_scope_ids,
       jsonb_agg(distinct 
         jsonb_build_object(
           'scope_id', coalesce(org_grants.scope_id, project_grants.scope_id),
           'delete_time', (
             select upper(valid_range) as delete_time
               from iam_scope_hst
              where public_id = coalesce(org_grants.scope_id, project_grants.scope_id)
              order by upper(valid_range) desc
              limit 1
           )
         )
       ) filter (where (org_grants.scope_id is not null and org_scope.public_id is null) or 
                       (project_grants.scope_id is not null and project_scope.public_id is null)) 
         as deleted_scope_details
from app_token_global
join app_token_permission_global
  on app_token_global.public_id = app_token_permission_global.app_token_id
left join app_token_permission_global_individual_org_grant_scope org_grants
  on app_token_permission_global.private_id = org_grants.permission_id
left join iam_scope org_scope
  on org_grants.scope_id = org_scope.public_id
left join app_token_permission_global_individual_project_grant_scope project_grants
  on app_token_permission_global.private_id = project_grants.permission_id
left join iam_scope project_scope
  on project_grants.scope_id = project_scope.public_id

where app_token_global.public_id = 'at_global_children_per_org'
group by app_token_permission_global.private_id,
         app_token_permission_global.description,
         app_token_permission_global.create_time,
         app_token_permission_global.grant_this_scope,
         app_token_permission_global.grant_scope,
         app_token_global.public_id;
