begin;

/*
  Dimensions are:
  -[x] date, time,
  -[x] target, host, host_set, host_catalog,
  -[x] user, auth_token,

  -[ ] worker,
  -[ ] address, port,
*/

  create table wh_host_dimension (
    id                            bigint generated always as identity primary key,

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

    project_id                    wt_public_id not null,
    project_name                  text not null,
    project_description           text not null,

    host_organization_id          wt_public_id not null,
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

  -- TODO(mgaffney) 09/2020: insert 0 row

  create table wh_user_dimension (
    id                            bigint generated always as identity primary key,

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

commit;
