// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hook97001

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
      -- find all global role ids with grant scope descendants and individual org or project grant scopes
      -- descendants already cover all orgs and projects so individual grant scopes are not necessary
      global_roles_with_overlap_descendants_and_individual(role_id) as (
        select role_id
          from iam_role_grant_scope
         where role_id in (select role_id from global_roles)
      group by role_id
        having
          count(*) filter (where scope_id_or_special like 'o_%' or scope_id_or_special like 'p_%') >=1 and
          count(*) filter (where scope_id_or_special = 'descendants') >= 1
      ),
      -- find all individual org or project grant scopes associated with role ids found to have overlapping grants
      -- filter out all special grants because we want to keep them and delete individual grant scopes
      global_descendants_overlap(role_id, role_scope_id, grant_scope_id) as (
        select rgs.role_id as role_id,
               r.scope_id as role_scope_id,
               rgs.scope_id_or_special as grant_scope_id
          from iam_role_grant_scope rgs
          join iam_role r on r.public_id = rgs.role_id
         -- skip special grants because we only need individually grant scopes in the result set
         where scope_id_or_special not in ('this', 'children', 'descendants')
           and role_id in (select role_id
                             from global_roles_with_overlap_descendants_and_individual)
      ),
      -- find all global role ids with grant scope children and individual project grant scopes
      -- children already cover all projects so individual grant scopes are not necessary
      global_roles_with_overlap_children_and_orgs(role_id) as (
        select role_id
          from iam_role_grant_scope
         where role_id in (select role_id from global_roles)
      group by role_id
        having
          count(*) filter (where scope_id_or_special like 'o_%') >= 1 and
          count(*) filter (where scope_id_or_special = 'children') >= 1
      ),
      -- find all individual project grant scopes associated with role ids found to have overlapping grants
      -- filter out all special grants because we want to keep them and delete individual grant scopes
      global_children_overlap(role_id, role_scope_id, grant_scope_id) as (
        select rgs.role_id as role_id,
               r.scope_id as role_scope_id,
               rgs.scope_id_or_special as grant_scope_id
          from iam_role_grant_scope rgs
          join iam_role r on r.public_id = rgs.role_id
         where scope_id_or_special not in ('this', 'children', 'descendants')
           and scope_id_or_special not like 'p_%' -- filter out projects because children + project is valid
           and role_id in (select role_id
                             from global_roles_with_overlap_children_and_orgs)
      ),
      -- find all global role ids with grant scope children and individual project grant scopes
      -- children already cover all projects so individual grant scopes are not necessary
      org_roles_with_overlap_children_and_projects(role_id) as (
        select role_id
          from iam_role_grant_scope
         where role_id in (select role_id from org_roles)
      group by role_id
        having
          count(*) filter (where scope_id_or_special like 'p_%') >= 1 and
          count(*) filter (where scope_id_or_special = 'children') >= 1
      ),
      -- find all individual project grant scopes associated with role ids found to have overlapping grants
      -- filter out all special grants because we want to keep them and delete individual grant scopes
      org_children_overlap(role_id, role_scope_id, grant_scope_id) as (
        select rgs.role_id as role_id,
               r.scope_id as role_scope_id,
               rgs.scope_id_or_special as grant_scope_id
          from iam_role_grant_scope rgs
          join iam_role r on r.public_id = rgs.role_id
         where scope_id_or_special not in ('this', 'children', 'descendants')
           and role_id in (select role_id
                             from org_roles_with_overlap_children_and_projects)
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

	getInvalidGrantsAssociationsQuery = baseQuery + `
	    select * from problems order by role_id, individual_grant_scope;
	`

	deleteInvalidGrantsAssociationsQuery = baseQuery + `,
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
