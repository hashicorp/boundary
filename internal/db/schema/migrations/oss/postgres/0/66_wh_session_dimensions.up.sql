-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- wh_upsert_host returns the wh_host_dimension id for p_host_id,
  -- p_host_set_id, and p_target_id. wh_upsert_host compares the current values
  -- in the wh_host_dimension with the current values in the operational tables
  -- for the provide parameters. If the values between the operational tables
  -- and the wh_host_dimension differ, a new row is inserted in the
  -- wh_host_dimension to match the current values in the operational tables and
  -- the new id is returned. If the values do not differ, the current id is
  -- returned.
  create or replace function wh_upsert_host(p_host_id wt_public_id, p_host_set_id wt_public_id, p_target_id wt_public_id) returns wh_dim_id
  as $$
  declare
    src     whx_host_dimension_target%rowtype;
    target  whx_host_dimension_target%rowtype;
    new_row wh_host_dimension%rowtype;
  begin
    select * into target
      from whx_host_dimension_target as t
     where t.host_id               = p_host_id
       and t.host_set_id           = p_host_set_id
       and t.target_id             = p_target_id;

    select target.id, t.* into src
      from whx_host_dimension_source as t
     where t.host_id               = p_host_id
       and t.host_set_id           = p_host_set_id
       and t.target_id             = p_target_id;

    if src is distinct from target then

      -- expire the current row
      update wh_host_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where host_id               = p_host_id
         and host_set_id           = p_host_set_id
         and target_id             = p_target_id
         and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_host_dimension (
             host_id,                    host_type,                  host_name,                       host_description,         host_address,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             host_organization_id,       host_organization_name,     host_organization_description,
             current_row_indicator,      row_effective_time,         row_expiration_time
      )
      select host_id,                    host_type,                  host_name,                       host_description,         host_address,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             host_organization_id,       host_organization_name,     host_organization_description,
             'Current',                  current_timestamp,          'infinity'::timestamptz
        from whx_host_dimension_source
       where host_id               = p_host_id
         and host_set_id           = p_host_set_id
         and target_id             = p_target_id
      returning * into new_row;

      return new_row.id;
    end if;
    return target.id;

  end;
  $$ language plpgsql;

  -- wh_upsert_user returns the wh_user_dimension id for p_user_id and
  -- p_auth_token_id. wh_upsert_user compares the current values in the
  -- wh_user_dimension with the current values in the operational tables for the
  -- provide parameters. If the values between the operational tables and the
  -- wh_user_dimension differ, a new row is inserted in the wh_user_dimension to
  -- match the current values in the operational tables and the new id is
  -- returned. If the values do not differ, the current id is returned.
  create or replace function wh_upsert_user(p_user_id wt_user_id, p_auth_token_id wt_public_id) returns wh_dim_id
  as $$
  declare
    src     whx_user_dimension_target%rowtype;
    target  whx_user_dimension_target%rowtype;
    new_row wh_user_dimension%rowtype;
    acct_id wt_public_id;
  begin
    select auth_account_id into strict acct_id
      from auth_token
     where public_id = p_auth_token_id;

    select * into target
      from whx_user_dimension_target as t
     where t.user_id               = p_user_id
       and t.auth_account_id       = acct_id;

    select target.id, t.* into src
      from whx_user_dimension_source as t
     where t.user_id               = p_user_id
       and t.auth_account_id       = acct_id;

    if src is distinct from target then

      -- expire the current row
      update wh_user_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where user_id               = p_user_id
         and auth_account_id       = acct_id
         and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_user_dimension (
             user_id,               user_name,              user_description,
             auth_account_id,       auth_account_type,      auth_account_name,             auth_account_description,
             auth_method_id,        auth_method_type,       auth_method_name,              auth_method_description,
             user_organization_id,  user_organization_name, user_organization_description,
             current_row_indicator, row_effective_time,     row_expiration_time
      )
      select user_id,               user_name,              user_description,
             auth_account_id,       auth_account_type,      auth_account_name,             auth_account_description,
             auth_method_id,        auth_method_type,       auth_method_name,              auth_method_description,
             user_organization_id,  user_organization_name, user_organization_description,
             'Current',             current_timestamp,      'infinity'::timestamptz
        from whx_user_dimension_source
       where user_id               = p_user_id
         and auth_account_id       = acct_id
      returning * into new_row;

      return new_row.id;
    end if;
    return target.id;

  end;
  $$ language plpgsql;
commit;
