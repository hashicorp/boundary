begin;

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
    return null;
  end;
  $$ language plpgsql;

  create trigger
    insert_wh_session_connection_fact
  after insert on session_connection
    for each row execute function insert_wh_session_connection_fact();



commit;
