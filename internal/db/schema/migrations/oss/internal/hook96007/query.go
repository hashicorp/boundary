// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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
         where scope_id_or_special not in ('this', 'children', 'descendants')
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
         where scope_id_or_special not in ('this', 'children', 'descendants')
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
      org_children_overlap(role_id, role_scope_id, grant_scope_id) as (
        select rgs.role_id as role_id,
               r.scope_id as role_scope_id,
               rgs.scope_id_or_special as grant_scope_id
          from iam_role_grant_scope rgs
          join iam_role r on r.public_id = rgs.role_id
         where scope_id_or_special not in ('this', 'children', 'descendants')
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
      problems (role_id, role_scope_id, covered_by_grant_scope, individual_grant_scope) as (
        select role_id        as role_id,
               role_scope_id  as role_scope_id,
               'descendants'  as covered_by_grant_scope,
               grant_scope_id as individual_grant_scope
          from global_descendants_overlap
         union
        select role_id        as role_id,
               role_scope_id  as role_scope_id,
               'children'     as covered_by_grant_scope,
               grant_scope_id as individual_grant_scope
          from global_children_overlap
         union
        select role_id        as role_id,
               role_scope_id  as role_scope_id,
               'children'     as covered_by_grant_scope,
               grant_scope_id as individual_grant_scope
          from org_children_overlap
      )`

	getIllegalAssociationsQuery = baseQuery + `
	    select * from problems order by role_id, individual_grant_scope;
	`

	deleteIllegalAssociationsQuery = baseQuery + `,
      deleted_grant_scope (role_id, scope_id_or_special) as (
           delete
             from iam_role_grant_scope
            where (role_id, scope_id_or_special) in (select role_id,
                                                            individual_grant_scope
                                                       from problems)
        returning role_id, scope_id_or_special
      ),
      deleted_problems (role_id, role_scope_id, covered_by_grant_scope, individual_grant_scope) as (
        select role_id                 as role_id,
               role_scope_id           as role_scope_id,
               covered_by_grant_scope  as covered_by_grant_scope,
               individual_grant_scope  as individual_grant_scope
          from problems
         where (role_id, individual_grant_scope) in (select role_id,
                                                            scope_id_or_special
                                                       from deleted_grant_scope)
      )
      select * from deleted_problems;`
)
