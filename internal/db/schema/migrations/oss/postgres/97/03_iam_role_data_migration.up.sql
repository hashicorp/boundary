-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Insert the predefined grant scope types for iam_role_global
  insert into iam_role_global_grant_scope_enm (name)
  values
    ('descendants'),
    ('children'),
    ('individual');

   -- Insert the predefined grant scope types for iam_role_org
  insert into iam_role_org_grant_scope_enm (name)
  values
    ('children'),
    ('individual');

  -- Insert any global roles that have an associated grant scope
  with aggregated_iam_role_grant_scope as (
    select r.role_id,
           json_agg (
             json_build_object (
               'create_time',         r.create_time,
               'scope_id_or_special', r.scope_id_or_special
             )
             order by r.create_time
           ) as grant_scope
      from iam_role_grant_scope r
  group by r.role_id
  ),
  grant_scope_values as (
    select a.role_id,
           -- if scope_id_or_special is 'this' set grant_this_role_scope to true
           -- if scope_id_or_special is 'global' set grant_this_role_scope to true
           -- if neither are present set grant_this_role_scope to false
           exists (
            select 1
              from jsonb_array_elements(a.grant_scope::jsonb) arr
             where arr->>'scope_id_or_special' = 'this' or arr->>'scope_id_or_special' = 'global'
           ) as grant_this_role_scope,
           -- if scope_id_or_special is 'descendants' set grant_scope to 'descendants'.
           -- if scope_id_or_special is 'children' set grant_scope to 'children'.
           -- if neither are present set grant_scope to 'individual' because
           -- the value could be a scope_id in which case the grant_scope should be 'individual'.
           -- if the value is 'this' then the grant_scope should be 'individual' as well
           -- because the grant_scope column cannot be null.
           case
            when exists (
              select 1
                from jsonb_array_elements(a.grant_scope::jsonb) arr
               where arr->>'scope_id_or_special' = 'descendants'
            ) then 'descendants'
            when exists (
              select 1
                from jsonb_array_elements(a.grant_scope::jsonb) arr
               where arr->>'scope_id_or_special' = 'children'
            ) then 'children'
            else 'individual'
           end as grant_scope,
           -- there should only be one create_time for when scope_id_or_special is 'this'
           -- so we can just pick the first create_time for this value
           (select (x->>'create_time')::wt_timestamp
              from jsonb_array_elements(a.grant_scope::jsonb) x
             where x->>'scope_id_or_special' = 'this'
          order by (x->>'create_time')::wt_timestamp
             limit 1
           ) as grant_this_role_scope_update_time,
           -- if scope_id_or_special is not 'this' then we can just pick the first create_time.
           (select (x->>'create_time')::wt_timestamp
              from jsonb_array_elements(a.grant_scope::jsonb) x
             where x->>'scope_id_or_special' != 'this'
          order by (x->>'create_time')::wt_timestamp
             limit 1
           ) as grant_scope_update_time
      from aggregated_iam_role_grant_scope a
  )
  insert into iam_role_global (
         public_id,
         scope_id,
         name,
         description,
         version,
         grant_this_role_scope,
         grant_scope,
         grant_this_role_scope_update_time,
         grant_scope_update_time,
         create_time,
         update_time
  )
  select r.public_id,
         r.scope_id,
         r.name,
         r.description,
         r.version,
         rs.grant_this_role_scope,
         rs.grant_scope,
         rs.grant_this_role_scope_update_time,
         rs.grant_scope_update_time,
         r.create_time,
         r.update_time
    from grant_scope_values rs
    join iam_role as r
      on rs.role_id = r.public_id
    join iam_scope as s
      on s.public_id = r.scope_id
   where s.type = 'global';

  -- Insert any remaining global roles that do not have an associated grant scope
  -- These roles will have a grant_scope of 'individual' and grant_this_role_scope of false
  insert into iam_role_global (
         public_id,
         scope_id,
         name,
         description,
         version,
         grant_this_role_scope,
         grant_scope,
         grant_this_role_scope_update_time,
         grant_scope_update_time,
         create_time,
         update_time
  )
  select public_id,
         scope_id,
         name,
         description,
         version,
         false,
         'individual',
         create_time,
         create_time,
         create_time,
         update_time
    from iam_role
   where scope_id = 'global'
      on conflict (public_id) do nothing;

  -- Insert any org-level roles with the appropriate grant scopes
  with aggregated_iam_role_grant_scope as (
    select r.role_id,
           json_agg (
             json_build_object (
               'create_time', r.create_time,
               'scope_id_or_special', r.scope_id_or_special
             )
             order by r.create_time
           ) as grant_scope
      from iam_role_grant_scope r
  group by r.role_id
  ),
  grant_scope_values as (
    select a.role_id,
           -- if scope_id_or_special is 'this' set grant_this_role_scope to true
           -- if not, set grant_this_role_scope to false
           exists (
             select 1
               from jsonb_array_elements(a.grant_scope::jsonb) arr
              where arr->>'scope_id_or_special' = 'this'
           ) as grant_this_role_scope,
           -- if scope_id_or_special is 'children' set grant_scope to 'children'.
           -- if not present, set grant_scope to 'individual' because
           -- the value could be a scope_id in which case the grant_scope should be 'individual'.
           -- if the value is 'this' then the grant_scope should be 'individual' as well
           -- because the grant_scope column cannot be null.
           case
             when exists (
               select 1
                 from jsonb_array_elements(a.grant_scope::jsonb) arr
                where arr->>'scope_id_or_special' = 'children'
             ) then 'children'
             else 'individual'
           end as grant_scope,
           -- there should only be one create_time for when scope_id_or_special is 'this'
           -- so we can just pick the first create_time for this value
           (select (x->>'create_time')::wt_timestamp
              from jsonb_array_elements(a.grant_scope::jsonb) x
             where x->>'scope_id_or_special' = 'this'
          order by (x->>'create_time')::wt_timestamp
             limit 1
           ) as grant_this_role_scope_update_time,
           -- if scope_id_or_special is not 'this' then we can just pick the first create_time.
           (select (x->>'create_time')::wt_timestamp
              from jsonb_array_elements(a.grant_scope::jsonb) x
             where x->>'scope_id_or_special' != 'this'
          order by (x->>'create_time')::wt_timestamp
             limit 1
           ) as grant_scope_update_time
      from aggregated_iam_role_grant_scope a
  )
  insert into iam_role_org (
         public_id,
         scope_id,
         name,
         description,
         version,
         grant_this_role_scope,
         grant_scope,
         grant_this_role_scope_update_time,
         grant_scope_update_time,
         create_time,
         update_time
  )
  select r.public_id,
         r.scope_id,
         r.name,
         r.description,
         r.version,
         rs.grant_this_role_scope,
         rs.grant_scope,
         rs.grant_this_role_scope_update_time,
         rs.grant_scope_update_time,
         r.create_time,
         r.update_time
    from grant_scope_values rs
    join iam_role as r
      on rs.role_id = r.public_id
    join iam_scope as s
      on s.public_id = r.scope_id
   where s.type = 'org';

  -- Insert any org roles that do not have an associated grant scope
  -- These roles will have a grant_scope of 'individual' and grant_this_role_scope of false
  insert into iam_role_org (
         public_id,
         scope_id,
         name,
         description,
         version,
         grant_this_role_scope,
         grant_scope,
         grant_this_role_scope_update_time,
         grant_scope_update_time,
         create_time,
         update_time
  )
  select public_id,
         scope_id,
         name,
         description,
         version,
         false,
         'individual',
         create_time,
         create_time,
         create_time,
         update_time
    from iam_role
   where scope_id like 'o_%'
      on conflict (public_id) do nothing;

  -- Update the iam_role_org table to set the grant_this_role_scope
  -- and grant_this_role_scope_update_time based on if they are granted 'this'
  with grant_scope_this as (
    select gs.role_id,
           gs.create_time
      from iam_role_grant_scope gs
      join iam_role_org as o
        on gs.role_id = o.public_id
     where scope_id_or_special = o.scope_id
  )
  update iam_role_org
     set grant_this_role_scope             = true,
         grant_this_role_scope_update_time = grant_scope_this.create_time
    from grant_scope_this
   where iam_role_org.public_id = grant_scope_this.role_id;

  -- Migrate project roles (if they have a scope_id, they get migrated)
  insert into iam_role_project (
         public_id,
         scope_id,
         name,
         description,
         version,
         grant_this_role_scope_update_time,
         create_time,
         update_time
  )
  select r.public_id,
         r.scope_id,
         r.name,
         r.description,
         r.version,
         r.create_time,
         r.create_time,
         r.update_time
    from iam_role r
    join iam_scope as s
      on s.public_id = r.scope_id
   where s.type = 'project';

  -- Update the iam_role_project table to set the grant_this_role_scope
  -- and grant_this_role_scope_update_time based on if they are granted 'this'
  with grant_scope_this as (
    select gs.role_id,
           gs.create_time,
           gs.scope_id_or_special
      from iam_role_grant_scope gs
      join iam_role_project as p
        on p.public_id = gs.role_id
  )
  update iam_role_project
     set grant_this_role_scope             = true,
         grant_this_role_scope_update_time = grant_scope_this.create_time
    from grant_scope_this
   where iam_role_project.public_id = grant_scope_this.role_id;

  -- Insert the predefined resource types
  insert into iam_grant_resource_enm (name)
  values
    ('*'),
    ('alias'),
    ('auth-method'),
    ('auth-token'),
    ('account'),
    ('billing'),
    ('controller'),
    ('credential'),
    ('credential-library'),
    ('credential-store'),
    ('group'),
    ('host'),
    ('host-catalog'),
    ('host-set'),
    ('managed-group'),
    ('policy'),
    ('role'),
    ('scope'),
    ('session'),
    ('session-recording'),
    ('storage-bucket'),
    ('target'),
    ('unknown'),
    ('user'),
    ('worker');

  -- any global roles that are granted specific org scopes are migrated to its individual grant scope table
  insert into iam_role_global_individual_org_grant_scope (
         role_id,
         grant_scope,
         scope_id,
         create_time
  )
  select rs.role_id,
         r.grant_scope,
         rs.scope_id_or_special,
         rs.create_time
    from iam_role_grant_scope as rs
    join iam_role_global      as r
      on r.public_id = rs.role_id
   where rs.scope_id_or_special like 'o_%';

  -- any global roles that are granted specific project scopes are migrated to its individual grant scope table
  insert into iam_role_global_individual_project_grant_scope (
         role_id,
         grant_scope,
         scope_id,
         create_time
  )
  select rs.role_id,
         r.grant_scope,
         rs.scope_id_or_special,
         rs.create_time
    from iam_role_grant_scope as rs
    join iam_role_global      as r
      on r.public_id = rs.role_id
   where rs.scope_id_or_special like 'p_%';

  -- any org roles that are granted specific project scopes are migrated to its individual grant scope table
  insert into iam_role_org_individual_grant_scope (
         role_id,
         grant_scope,
         scope_id,
         create_time
  )
  select rs.role_id,
         r.grant_scope,
         rs.scope_id_or_special,
         rs.create_time
    from iam_role_grant_scope as rs
    join iam_role_org         as r
      on r.public_id = rs.role_id
   where rs.scope_id_or_special like 'p_%';

  insert into oplog_ticket (name, version)
  values ('iam_role_global',  1),
         ('iam_role_org',     1),
         ('iam_role_project', 1);

commit;