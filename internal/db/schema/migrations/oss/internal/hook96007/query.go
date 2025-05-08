package hook96007

const getIllegalAssociationsQuery = `
      with
	  global_roles (role_id) as (
	    select public_id
          from iam_role 
         where scope_id = 'global'
      ),
	  org_roles (role_id) as (
	    select public_id
          from iam_role 
         where scope_id like 'o_%'
      ),
	  proj_roles (role_id) as (
	    select public_id
          from iam_role 
         where scope_id like 'p_%'
      ),
      global_roles_descendants_overlap_grant_scopes (role_id, special_grant, individual_grants) as (
        select role_id,
          max(scope_id_or_special) filter (where scope_id_or_special in ('descendants')) as special_grant_scope,
          array_agg (scope_id_or_special) filter (where scope_id_or_special like 'o_%' or scope_id_or_special like 'p_%') as individual_grant_scope
          from iam_role_grant_scope
         where role_id in (select role_id from global_roles)
         group by role_id
      ),
      global_roles_children_overlap_grant_scopes (role_id, special_grant, individual_grants) as (
        select role_id,
          max(scope_id_or_special) filter (where scope_id_or_special in ('children')) as special_grant_scope,
          array_agg (scope_id_or_special) filter (where scope_id_or_special like 'o_%') as individual_grant_scope
          from iam_role_grant_scope
         where role_id in (select role_id from global_roles)
         group by role_id
      ),
      org_roles_overlap_grant_scopes (role_id, special_grant, individual_grants) as (
        select role_id,
          max(scope_id_or_special) filter (where scope_id_or_special in ('children')) as special_grant_scope,
          array_agg (scope_id_or_special) filter (where scope_id_or_special like 'p_%') as individual_grant_scope
          from iam_role_grant_scope
         where role_id in (select role_id from org_roles)
         group by role_id
      )
      select gs.role_id as role_id,
             r.scope_id as scope_id,
             gs.special_grant as special_grant,
             array_to_string(gs.individual_grants, ', ') as individual_grants
        from global_roles_descendants_overlap_grant_scopes gs
        join iam_role r on (gs.role_id  = r.public_id)
       where special_grant is not null 
         and individual_grants is not null
      union 
      select gs.role_id as role_id,
             r.scope_id as scope_id,
             gs.special_grant as special_grant,
             array_to_string(gs.individual_grants, ', ') as individual_grants
        from global_roles_children_overlap_grant_scopes gs
        join iam_role r on (gs.role_id  = r.public_id)
       where special_grant is not null 
         and individual_grants is not null
      union 
      select gs.role_id as role_id,
             r.scope_id as scope_id,
             gs.special_grant as special_grant,
             array_to_string(gs.individual_grants, ', ') as individual_grants
        from org_roles_overlap_grant_scopes gs
        join iam_role r on (gs.role_id  = r.public_id)
       where special_grant is not null 
         and individual_grants is not null
       order by role_id
`
