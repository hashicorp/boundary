begin;

  create or replace function rollup_connections(p_session_id wt_public_id)
    returns void
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

  create or replace function insert_wh_session_fact()
    returns trigger
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

  create trigger
    insert_wh_session_fact
  after insert on session
    for each row execute function insert_wh_session_fact();

  create or replace function insert_wh_session_connection_fact()
    returns trigger
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
    perform rollup_connections(new.session_id);
    return null;
  end;
  $$ language plpgsql;

  create trigger
    insert_wh_session_connection_fact
  after insert on session_connection
    for each row execute function insert_wh_session_connection_fact();

  create or replace function update_wh_session_connection_fact()
    returns trigger
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
    perform rollup_connections(new.session_id);
    return null;
  end;
  $$ language plpgsql;

  create trigger
    update_wh_session_connection_fact
  after update on session_connection
    for each row execute function update_wh_session_connection_fact();


commit;
