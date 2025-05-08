package hook96007

const (
	baseQuery = `
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
      global_descendants_overlap(role_id, role_scope_id, grant_scope_id) as (
        select rgs.role_id as role_id,
               r.scope_id as role_scope_id,
        	   rgs.scope_id_or_special as grant_scope_id
          from iam_role_grant_scope rgs
          join iam_role r on r.public_id = rgs.role_id
         where scope_id_or_special != 'this' 
           and role_id in (
           select role_id
             from iam_role_grant_scope
            where role_id in (select role_id from global_roles)
         group by role_id
           having 
             count(*) filter (where scope_id_or_special like 'o_%' or scope_id_or_special like 'p_%') >=1 and
             count(*) filter (where scope_id_or_special = 'descendants') >= 1
         )
      ),
      global_children_overlap(role_id, role_scope_id, grant_scope_id) as (
        select rgs.role_id as role_id,
               r.scope_id as role_scope_id,
        	   rgs.scope_id_or_special as grant_scope_id
          from iam_role_grant_scope rgs
          join iam_role r on r.public_id = rgs.role_id
         where scope_id_or_special != 'this' 
           and scope_id_or_special not like 'p_%' -- filter out projects because children + project is valid
           and role_id in (
           select role_id
             from iam_role_grant_scope
            where role_id in (select role_id from global_roles)
         group by role_id
           having 
             count(*) filter (where scope_id_or_special like 'o_%') >= 1 and
             count(*) filter (where scope_id_or_special = 'children') >= 1
         )
      ),
      org_overlap_grant_scopes(role_id, role_scope_id, grant_scope_id) as (
        select rgs.role_id as role_id,
               r.scope_id as role_scope_id,
        	   rgs.scope_id_or_special as grant_scope_id
          from iam_role_grant_scope rgs
          join iam_role r on r.public_id = rgs.role_id
         where scope_id_or_special != 'this' 
           and role_id in (
           select role_id
             from iam_role_grant_scope
            where role_id in (select role_id from org_roles)
         group by role_id
           having 
             count(*) filter (where scope_id_or_special like 'p_%') >= 1 and
             count(*) filter (where scope_id_or_special = 'children') >= 1
         ) 
      ),
      problems (role_id, role_scope_id, grant_scope_id) as (
        select role_id,
               role_scope_id,
               grant_scope_id
          from global_descendants_overlap
         union
        select role_id,
               role_scope_id,
               grant_scope_id
          from global_children_overlap
         union
        select role_id,
               role_scope_id,
               grant_scope_id
          from org_overlap_grant_scopes
      )
`

	getIllegalAssociationsQuery = baseQuery + `
      select role_id, 
             role_scope_id,
			 max(grant_scope_id) FILTER (WHERE grant_scope_id IN ('descendants', 'children')) AS special_grant_scope,
			 string_agg(grant_scope_id, ', ' order by grant_scope_id) FILTER (WHERE grant_scope_id NOT IN ('descendants', 'children')) AS individual_grant_scope
        from problems
    group by role_id, role_scope_id
	order by role_id;
`
)
