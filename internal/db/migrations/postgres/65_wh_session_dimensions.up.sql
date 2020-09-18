begin;

  create table wh_host_dimension (
    -- random id generated using encode(digest(gen_random_bytes(16), 'sha256'), 'base64')
    -- this is done to prevent conflicts with rows in other clusters
    -- which enables warehouse data from multiple clusters to be loaded into a
    -- single database instance
    id                            wh_dim_id primary key default wh_dim_id(),

    host_id                       wt_public_id not null,
    host_type                     text not null,
    host_name                     text not null,
    host_description              text not null,
    host_address                  text not null,

    host_set_id                   wt_public_id not null,
    host_set_type                 text not null,
    host_set_name                 text not null,
    host_set_description          text not null,

    host_catalog_id               wt_public_id not null,
    host_catalog_type             text not null,
    host_catalog_name             text not null,
    host_catalog_description      text not null,

    target_id                     wt_public_id not null,
    target_type                   text not null,
    target_name                   text not null,
    target_description            text not null,

    project_id                    wt_scope_id not null,
    project_name                  text not null,
    project_description           text not null,

    host_organization_id          wt_scope_id not null,
    host_organization_name        text not null,
    host_organization_description text not null,

    current_row_indicator         text not null,
    row_effective_time            wt_timestamp,
    row_expiration_time           wt_timestamp
  );

  -- https://www.postgresql.org/docs/current/indexes-partial.html
  create unique index wh_host_dim_current_constraint
    on wh_host_dimension (target_id, host_set_id, host_id)
    where current_row_indicator = 'Current';

  -- The whx_host_dimension_source and whx_host_dimension_target views are used
  -- by an insert trigger to determine if the current row for the dimension has
  -- changed and new one needs to be inserted. The first column in the target
  -- view must be the current warehouse id and all remaining columns must match
  -- the columns in the source view.

  -- The whx_host_dimension_source view shows the current values in the
  -- operational tables of the host dimension.
  create view whx_host_dimension_source as
  select -- id is the first column in the target view
         h.public_id                     as host_id,
         'static host'                   as host_type,
         coalesce(h.name, 'None')        as host_name,
         coalesce(h.description, 'None') as host_description,
         coalesce(h.address, 'Unknown')  as host_address,
         s.public_id                     as host_set_id,
         'static host set'               as host_set_type,
         coalesce(s.name, 'None')        as host_set_name,
         coalesce(s.description, 'None') as host_set_description,
         c.public_id                     as host_catalog_id,
         'static host catalog'           as host_catalog_type,
         coalesce(c.name, 'None')        as host_catalog_name,
         coalesce(c.description, 'None') as host_catalog_description,
         t.public_id                     as target_id,
         'tcp target'                    as target_type,
         coalesce(t.name, 'None')        as target_name,
         coalesce(t.description, 'None') as target_description,
         p.public_id                     as project_id,
         coalesce(p.name, 'None')        as project_name,
         coalesce(p.description, 'None') as project_description,
         o.public_id                     as host_organization_id,
         coalesce(o.name, 'None')        as host_organization_name,
         coalesce(o.description, 'None') as host_organization_description
    from static_host as h,
         static_host_catalog as c,
         static_host_set_member as m,
         static_host_set as s,
         target_host_set as ts,
         target_tcp as t,
         iam_scope as p,
         iam_scope as o
   where h.catalog_id = c.public_id
     and h.public_id = m.host_id
     and s.public_id = m.set_id
     and t.public_id = ts.target_id
     and s.public_id = ts.host_set_id
     and p.public_id = t.scope_id
     and p.type = 'project'
     and o.public_id = p.parent_id
     and o.type = 'org'
  ;

  -- The whx_host_dimension_target view shows the rows in the wh_host_dimension
  -- table marked as 'Current'.
  create view whx_host_dimension_target as
  select id,
         host_id,
         host_type,
         host_name,
         host_description,
         host_address,
         host_set_id,
         host_set_type,
         host_set_name,
         host_set_description,
         host_catalog_id,
         host_catalog_type,
         host_catalog_name,
         host_catalog_description,
         target_id,
         target_type,
         target_name,
         target_description,
         project_id,
         project_name,
         project_description,
         host_organization_id,
         host_organization_name,
         host_organization_description
    from wh_host_dimension
   where current_row_indicator = 'Current'
  ;

  -- TODO(mgaffney) 09/2020: insert 0 row

  create table wh_user_dimension (
    -- random id generated using encode(digest(gen_random_bytes(16), 'sha256'), 'base64')
    -- this is done to prevent conflicts with rows in other clusters
    -- which enables warehouse data from multiple clusters to be loaded into a
    -- single database instance
    id                            wh_dim_id primary key default wh_dim_id(),

    user_id                       wt_public_id not null,
    user_name                     text not null,
    user_description              text not null,

    auth_account_id               wt_public_id not null,
    auth_account_type             text not null,
    auth_account_name             text not null,
    auth_account_description      text not null,

    auth_method_id                wt_public_id not null,
    auth_method_type              text not null,
    auth_method_name              text not null,
    auth_method_description       text not null,

    user_organization_id          wt_public_id not null,
    user_organization_name        text not null,
    user_organization_description text not null,

    current_row_indicator         text not null,
    row_effective_time            wt_timestamp,
    row_expiration_time           wt_timestamp
  );

  -- The whx_user_dimension_source and whx_user_dimension_target views are used
  -- by an insert trigger to determine if the current row for the dimension has
  -- changed and new one needs to be inserted. The first column in the target
  -- view must be the current warehouse id and all remaining columns must match
  -- the columns in the source view.

  -- The whx_user_dimension_source view shows the current values in the
  -- operational tables of the user dimension.
  create view whx_user_dimension_source as
       select -- id is the first column in the target view
              u.public_id                       as user_id,
              coalesce(u.name, 'None')          as user_name,
              coalesce(u.description, 'None')   as user_description,
              coalesce(aa.public_id, 'None')    as auth_account_id,
              'password auth account'           as auth_account_type,
              coalesce(apa.name, 'None')        as auth_account_name,
              coalesce(apa.description, 'None') as auth_account_description,
              coalesce(am.public_id, 'None')    as auth_method_id,
              'password auth method'            as auth_method_type,
              coalesce(apm.name, 'None')        as auth_method_name,
              coalesce(apm.description, 'None') as auth_method_description,
              org.public_id                     as user_organization_id,
              coalesce(org.name, 'None')        as user_organization_name,
              coalesce(org.description, 'None') as user_organization_description
         from iam_user as u
    left join auth_account as aa on           u.public_id = aa.iam_user_id
    left join auth_method as am on            aa.auth_method_id = am.public_id
    left join auth_password_account as apa on aa.public_id = apa.public_id
    left join auth_password_method as apm on  am.public_id = apm.public_id
         join iam_scope as org on             u.scope_id = org.public_id
  ;

  -- The whx_user_dimension_target view shows the rows in the wh_user_dimension
  -- table marked as 'Current'.
  create view whx_user_dimension_target as
    select id,
           user_id,
           user_name,
           user_description,
           auth_account_id,
           auth_account_type,
           auth_account_name,
           auth_account_description,
           auth_method_id,
           auth_method_type,
           auth_method_name,
           auth_method_description,
           user_organization_id,
           user_organization_name,
           user_organization_description
      from wh_user_dimension
     where current_row_indicator = 'Current'
  ;

commit;
