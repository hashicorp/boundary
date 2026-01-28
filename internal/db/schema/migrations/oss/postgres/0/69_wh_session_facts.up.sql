-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- wh_rollup_connections calculates the aggregate values from
  -- wh_session_connection_accumulating_fact for p_session_id and updates
  -- wh_session_accumulating_fact for p_session_id with those values.
  create or replace function wh_rollup_connections(p_session_id wt_public_id) returns void
  as $$
  declare
    session_row wh_session_accumulating_fact%rowtype;
  begin
    with
    session_totals (session_id, total_connection_count, total_bytes_up, total_bytes_down) as (
      select session_id,
             sum(connection_count),
             sum(bytes_up),
             sum(bytes_down)
        from wh_session_connection_accumulating_fact
       where session_id = p_session_id
       group by session_id
    )
    update wh_session_accumulating_fact
       set total_connection_count = session_totals.total_connection_count,
           total_bytes_up         = session_totals.total_bytes_up,
           total_bytes_down       = session_totals.total_bytes_down
      from session_totals
     where wh_session_accumulating_fact.session_id = session_totals.session_id
    returning wh_session_accumulating_fact.* into strict session_row;
  end;
  $$ language plpgsql;

  --
  -- Session triggers
  --

  -- wh_insert_session returns an after insert trigger for the session table
  -- which inserts a row in wh_session_accumulating_fact for the new session.
  -- wh_insert_session also calls the wh_upsert_host and wh_upsert_user
  -- functions which can result in new rows in wh_host_dimension and
  -- wh_user_dimension respectively.
  create or replace function wh_insert_session() returns trigger
  as $$
  declare
    new_row wh_session_accumulating_fact%rowtype;
  begin
    with
    pending_timestamp (date_dim_id, time_dim_id, ts) as (
      select wh_date_id(start_time), wh_time_id(start_time), start_time
        from session_state
       where session_id = new.public_id
         and state = 'pending'
    )
    insert into wh_session_accumulating_fact (
           session_id,
           auth_token_id,
           host_id,
           user_id,
           session_pending_date_id,
           session_pending_time_id,
           session_pending_time
    )
    select new.public_id,
           new.auth_token_id,
           wh_upsert_host(new.host_id, new.host_set_id, new.target_id),
           wh_upsert_user(new.user_id, new.auth_token_id),
           pending_timestamp.date_dim_id,
           pending_timestamp.time_dim_id,
           pending_timestamp.ts
      from pending_timestamp
      returning * into strict new_row;
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session after insert on session
    for each row execute function wh_insert_session();

  --
  -- Session Connection triggers
  --

  -- wh_insert_session_connection returns an after insert trigger for the
  -- session_connection table which inserts a row in
  -- wh_session_connection_accumulating_fact for the new session connection.
  -- wh_insert_session_connection also calls wh_rollup_connections which can
  -- result in updates to wh_session_accumulating_fact.
  create or replace function wh_insert_session_connection() returns trigger
  as $$
  declare
    new_row wh_session_connection_accumulating_fact%rowtype;
  begin
    with
    authorized_timestamp (date_dim_id, time_dim_id, ts) as (
      select wh_date_id(start_time), wh_time_id(start_time), start_time
        from session_connection_state
       where connection_id = new.public_id
         and state = 'authorized'
    ),
    session_dimension (host_dim_id, user_dim_id) as (
      select host_id, user_id
        from wh_session_accumulating_fact
       where session_id = new.session_id
    )
    insert into wh_session_connection_accumulating_fact (
           connection_id,
           session_id,
           host_id,
           user_id,
           connection_authorized_date_id,
           connection_authorized_time_id,
           connection_authorized_time,
           client_tcp_address,
           client_tcp_port_number,
           endpoint_tcp_address,
           endpoint_tcp_port_number,
           bytes_up,
           bytes_down
    )
    select new.public_id,
           new.session_id,
           session_dimension.host_dim_id,
           session_dimension.user_dim_id,
           authorized_timestamp.date_dim_id,
           authorized_timestamp.time_dim_id,
           authorized_timestamp.ts,
           new.client_tcp_address,
           new.client_tcp_port,
           new.endpoint_tcp_address,
           new.endpoint_tcp_port,
           new.bytes_up,
           new.bytes_down
      from authorized_timestamp,
           session_dimension
      returning * into strict new_row;
    perform wh_rollup_connections(new.session_id);
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session_connection after insert on session_connection
    for each row execute function wh_insert_session_connection();

  -- Updated in 27/01_disable_terminate_session.up.sql
  -- wh_update_session_connection returns an after update trigger for the
  -- session_connection table which updates a row in
  -- wh_session_connection_accumulating_fact for the session connection.
  -- wh_update_session_connection also calls wh_rollup_connections which can
  -- result in updates to wh_session_accumulating_fact.
  create or replace function wh_update_session_connection() returns trigger
  as $$
  declare
    updated_row wh_session_connection_accumulating_fact%rowtype;
  begin
        update wh_session_connection_accumulating_fact
           set client_tcp_address       = new.client_tcp_address,
               client_tcp_port_number   = new.client_tcp_port,
               endpoint_tcp_address     = new.endpoint_tcp_address,
               endpoint_tcp_port_number = new.endpoint_tcp_port,
               bytes_up                 = new.bytes_up,
               bytes_down               = new.bytes_down
         where connection_id = new.public_id
     returning * into strict updated_row;
    perform wh_rollup_connections(new.session_id);
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_update_session_connection after update on session_connection
    for each row execute function wh_update_session_connection();

  --
  -- Session State trigger
  --

  -- wh_insert_session_state returns an after insert trigger for the
  -- session_state table which updates wh_session_accumulating_fact.
  create or replace function wh_insert_session_state() returns trigger
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

    date_col = 'session_' || new.state || '_date_id';
    time_col = 'session_' || new.state || '_time_id';
    ts_col   = 'session_' || new.state || '_time';

    q = format('update wh_session_accumulating_fact
                   set (%I, %I, %I) = (select wh_date_id(%L), wh_time_id(%L), %L::timestamptz)
                 where session_id = %L
                returning *',
                date_col,       time_col,       ts_col,
                new.start_time, new.start_time, new.start_time,
                new.session_id);
    execute q into strict session_row;

    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session_state after insert on session_state
    for each row execute function wh_insert_session_state();

  --
  -- Session Connection State trigger
  --

  -- wh_insert_session_connection_state returns an after insert trigger for the
  -- session_connection_state table which updates
  -- wh_session_connection_accumulating_fact.
  create or replace function wh_insert_session_connection_state() returns trigger
  as $$
  declare
    date_col text;
    time_col text;
    ts_col text;
    q text;
    connection_row wh_session_connection_accumulating_fact%rowtype;
  begin
    if new.state = 'authorized' then
      -- The authorized state is the first state which is handled by the
      -- wh_insert_session_connection trigger. The update statement in this
      -- trigger will fail for the authorized state because the row for the
      -- session connection has not yet been inserted into the
      -- wh_session_connection_accumulating_fact table.
      return null;
    end if;

    date_col = 'connection_' || new.state || '_date_id';
    time_col = 'connection_' || new.state || '_time_id';
    ts_col   = 'connection_' || new.state || '_time';

    q = format('update wh_session_connection_accumulating_fact
                   set (%I, %I, %I) = (select wh_date_id(%L), wh_time_id(%L), %L::timestamptz)
                 where connection_id = %L
                returning *',
                date_col,       time_col,       ts_col,
                new.start_time, new.start_time, new.start_time,
                new.connection_id);
    execute q into strict connection_row;

    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session_connection_state after insert on session_connection_state
    for each row execute function wh_insert_session_connection_state();

commit;
