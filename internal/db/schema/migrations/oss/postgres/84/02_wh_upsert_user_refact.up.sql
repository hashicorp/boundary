-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  drop trigger wh_insert_session on session;
  drop function wh_insert_session;
  drop function wh_upsert_user;

  -- Replaces function from 15/01_wh_rename_key_columns.up.sql
  create function wh_upsert_user(p_auth_token_id wt_public_id) returns wh_dim_key
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
     where t.auth_account_id = acct_id;

    select target.key, t.* into src
      from whx_user_dimension_source as t
     where t.auth_account_id = acct_id;

    if src is distinct from target then

      -- expire the current row
      update wh_user_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where auth_account_id       = acct_id
         and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_user_dimension (
             user_id,                  user_name,              user_description,
             auth_account_id,          auth_account_type,      auth_account_name,             auth_account_description,
             auth_account_external_id, auth_account_full_name, auth_account_email,
             auth_method_id,           auth_method_type,       auth_method_name,              auth_method_description,
             auth_method_external_id,
             user_organization_id,     user_organization_name, user_organization_description,
             current_row_indicator,    row_effective_time,     row_expiration_time
      )
      select user_id,                  user_name,              user_description,
             auth_account_id,          auth_account_type,      auth_account_name,             auth_account_description,
             auth_account_external_id, auth_account_full_name, auth_account_email,
             auth_method_id,           auth_method_type,       auth_method_name,              auth_method_description,
             auth_method_external_id,
             user_organization_id,     user_organization_name, user_organization_description,
             'Current',                current_timestamp,      'infinity'::timestamptz
        from whx_user_dimension_source
       where auth_account_id = acct_id
      returning * into new_row;

      return new_row.key;
    end if;
    return target.key;

  end;
  $$ language plpgsql;
  comment on function wh_upsert_user is
    'wh_upsert_user a function insert or updates the wh_user_dimension table'
    'for the user that corresponds to the provided auth_token_id.';

  -- Replaces function from 60/03_wh_sessions.up.sql
  -- Replaced in 92/02_session_state_tstzrange.up.sql
  create function wh_insert_session() returns trigger
  as $$
  declare
    new_row wh_session_accumulating_fact%rowtype;
  begin
    with
    pending_timestamp (date_dim_key, time_dim_key, ts) as (
      select wh_date_key(start_time), wh_time_key(start_time), start_time
        from session_state
       where session_id = new.public_id
         and state      = 'pending'
    )
    insert into wh_session_accumulating_fact (
           session_id,
           auth_token_id,
           host_key,
           user_key,
           credential_group_key,
           session_pending_date_key,
           session_pending_time_key,
           session_pending_time
    )
    select new.public_id,
           new.auth_token_id,
           'no host source', -- will be updated by wh_upsert_host
           wh_upsert_user(new.auth_token_id),
           'no credentials', -- will be updated by wh_upsert_credential_group
           pending_timestamp.date_dim_key,
           pending_timestamp.time_dim_key,
           pending_timestamp.ts
      from pending_timestamp
      returning * into strict new_row;
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session after insert on session
    for each row execute procedure wh_insert_session();

commit;
