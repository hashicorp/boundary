-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- Add new active_time_range column that will replace two start_time, end_time columns.
  -- Also drop a number of constraints on the start_time, end_time columns. This will allow
  -- from dropping these columns after the new column has been set with the correct data.
      alter table session_state
       add column active_time_range tstzrange not null default tstzrange(now(), null, '[]'),
  drop constraint end_times_in_sequence,
  drop constraint previous_end_time_and_start_time_in_sequence,
  drop constraint start_and_end_times_in_sequence,
  drop constraint session_state_session_id_previous_end_time_fkey;

  -- Set the new active_time_range column for any existing rows using start_time and end_time.
  update session_state
     set active_time_range = tstzrange(start_time, end_time, '[)');

  -- Replaces view from 72/03/session_list_perf_fix.up.sql
  -- Switch view to tuse the new column. This also eliminates the previous_end_time column
  -- from the view, since it also will be dropped.
  drop view session_list;
  create view session_list as
      select s.public_id,
             s.user_id,
             shsh.host_id,
             shsh.host_set_id,
             s.target_id,
             s.auth_token_id,
             s.project_id,
             s.certificate,
             s.expiration_time,
             s.termination_reason,
             s.create_time,
             s.update_time,
             s.version,
             s.endpoint,
             s.connection_limit,
             ss.state,
             lower(ss.active_time_range) as start_time,
             upper(ss.active_time_range) as end_time
        from session s
        join session_state            ss on s.public_id = ss.session_id
   left join session_host_set_host  shsh on s.public_id = shsh.session_id;

  -- Now we can finally drop the old columns and add a constraint on the new column
  -- that ensures there are no overlaps on the active_time_range for a given session.
     alter table session_state
     drop column start_time,
     drop column end_time,
     drop column previous_end_time,
  add constraint session_state_active_time_range_excl
   exclude using gist (session_id        with =,
                       active_time_range with &&),
  add constraint active_time_range_not_empty
           check (not isempty(active_time_range));

  -- There are still a number of functions that reference the old columns.
  -- These all need to be updated to use the new column instead.

  -- Replaces trigger from 0/50_session.up.sql
  drop trigger immutable_columns on session_state;
  create trigger immutable_columns before update on session_state
    for each row execute procedure immutable_columns('session_id', 'state');

  -- Replaces function from 28/02_prior_session_trigger.up.sql
  drop trigger insert_session_state on session_state;
  drop function insert_session_state();
  create function insert_session_state() returns trigger
  as $$
  declare
      old_col_state text;
  begin
       update session_state
          set active_time_range = tstzrange(lower(active_time_range), now(), '[)')
        where session_id = new.session_id
          and upper(active_time_range) is null
    returning state
         into old_col_state;

    if not found then
      new.prior_state = 'pending';
    else
      new.prior_state = old_col_state;
    end if;

    new.active_time_range = tstzrange(now(), null, '[]');

    return new;
  end;
  $$ language plpgsql;

  create trigger insert_session_state before insert on session_state
      for each row execute procedure insert_session_state();

  -- Replaces function from 84/02_wh_upsert_user_refact.up.sql
  drop trigger wh_insert_session on session;
  drop function wh_insert_session;
  create function wh_insert_session() returns trigger
  as $$
  declare
    new_row wh_session_accumulating_fact%rowtype;
  begin
    with
    pending_timestamp (date_dim_key, time_dim_key, ts) as (
      select wh_date_key(lower(active_time_range)), wh_time_key(lower(active_time_range)), lower(active_time_range)
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

  -- Replaces function from 15/01_wh_rename_key_columns.up.sql
  drop trigger wh_insert_session_state on session_state;
  drop function wh_insert_session_state;

  create function wh_insert_session_state() returns trigger
  as $$
  declare
    date_col text;
    time_col text;
    ts_col text;
    q text;
    session_row wh_session_accumulating_fact%rowtype;
  begin
    if new.state = 'pending' then
      -- The pending state is the first state which is handled by the
      -- wh_insert_session trigger. The update statement in this trigger will
      -- fail for the pending state because the row for the session has not yet
      -- been inserted into the wh_session_accumulating_fact table.
      return null;
    end if;

    date_col = 'session_' || new.state || '_date_key';
    time_col = 'session_' || new.state || '_time_key';
    ts_col   = 'session_' || new.state || '_time';

    q = format('   update wh_session_accumulating_fact
                      set (%I, %I, %I) = (select wh_date_key(%L), wh_time_key(%L), %L::timestamptz)
                    where session_id = %L
                returning *',
                date_col,       time_col,       ts_col,
                lower(new.active_time_range), lower(new.active_time_range), lower(new.active_time_range),
                new.session_id);
    execute q into strict session_row;

    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session_state after insert on session_state
    for each row execute function wh_insert_session_state();
commit;
