-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
-- Updating definition from 16/05_wh_credential_dimension.up.sql
-- Remove call to wh_rollup_connections(new.session_id) from function
drop trigger wh_insert_session_connection on session_connection;
drop function wh_insert_session_connection();

-- Updated in 90/01_remove_session_connection_state
create function wh_insert_session_connection() returns trigger
as $$
declare
  new_row wh_session_connection_accumulating_fact%rowtype;
begin
with
    authorized_timestamp (date_dim_key, time_dim_key, ts) as (
        select wh_date_key(start_time), wh_time_key(start_time), start_time
        from session_connection_state
        where connection_id = new.public_id
          and state = 'authorized'
    ),
    session_dimension (host_dim_key, user_dim_key, credential_group_dim_key) as (
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
       session_dimension.host_dim_key,
       session_dimension.user_dim_key,
       session_dimension.credential_group_dim_key,
       authorized_timestamp.date_dim_key,
       authorized_timestamp.time_dim_key,
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

create trigger wh_insert_session_connection after insert on session_connection
    for each row execute function wh_insert_session_connection();

-- Updating definition from 0/69_wh_session_facts.up.sql
-- Remove call to wh_rollup_connections(new.session_id) from function
drop trigger wh_update_session_connection on session_connection;
drop function wh_update_session_connection;

create function wh_update_session_connection() returns trigger
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
return null;
end;
$$ language plpgsql;

create trigger wh_update_session_connection after update on session_connection
    for each row execute function wh_update_session_connection();

create function wh_session_rollup() returns trigger
as $$
begin
    if new.termination_reason is not null then
        -- Rollup will fail if no connections were made for a session
        if exists (select from session_connection where session_id = new.public_id) then
            perform wh_rollup_connections(new.public_id);
        end if;
    end if;
return null;
end;
$$ language plpgsql;

create trigger wh_rollup_connections_on_session_termination after update of termination_reason on session
    for each row execute procedure wh_session_rollup();

commit;
