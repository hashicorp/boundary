begin;
  alter table wh_session_connection_accumulating_fact
    add column credential_group_key wh_dim_id not null
    default 'no credentials'
    references wh_credential_group (key)
    on delete restrict
    on update cascade;
  alter table wh_session_connection_accumulating_fact
    alter column credential_group_key drop default;

  drop trigger wh_insert_session_connection on session_connection;
  drop function wh_insert_session_connection;
  create function wh_insert_session_connection()
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
    session_dimension (host_dim_id, user_dim_id, credential_group_dim_id) as (
      select host_key, user_key, credential_group_key
        from wh_session_accumulating_fact
       where session_id = new.session_id
    )
    insert into wh_session_connection_accumulating_fact (
           connection_id,
           session_id,
           host_key,
           user_key,
           credential_group_key,
           connection_authorized_date_key,
           connection_authorized_time_key,
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
           session_dimension.credential_group_dim_id,
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

  create trigger wh_insert_session_connection
    after insert on session_connection
    for each row
    execute function wh_insert_session_connection();
commit;

