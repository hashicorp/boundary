-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table wh_session_accumulating_fact
    add column credential_group_key wh_dim_key not null default 'Unknown'
    references wh_credential_group (key)
    on delete restrict
    on update cascade;

  alter table wh_session_accumulating_fact
    alter column credential_group_key drop default;

  -- replaces function from 15/01_wh_rename_key_columns.up.sql
  -- replaced function in 60/03_wh_sessions.up.sql
  drop trigger wh_insert_session on session;
  drop function wh_insert_session;

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
           wh_upsert_host(new.host_id, new.host_set_id, new.target_id),
           wh_upsert_user(new.user_id, new.auth_token_id),
           'no credentials', -- will be updated by wh_upsert_credentail_group
           pending_timestamp.date_dim_key,
           pending_timestamp.time_dim_key,
           pending_timestamp.ts
      from pending_timestamp
      returning * into strict new_row;
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session after insert on session
    for each row execute function wh_insert_session();

commit;
