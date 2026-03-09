-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Remove the session_connection_state table and any related triggers
  drop trigger update_connection_state_on_closed_reason on session_connection;
  drop function update_connection_state_on_closed_reason();

  drop trigger insert_session_connection_state on session_connection_state;
  drop function insert_session_connection_state();

  drop trigger update_session_state_on_termination_reason on session;
  drop function update_session_state_on_termination_reason();

  drop trigger insert_new_connection_state on session_connection;
  drop function insert_new_connection_state();

  drop trigger immutable_columns on session_connection_state;

  drop trigger wh_insert_session_connection_state on session_connection_state;
  drop function wh_insert_session_connection_state();

  drop trigger wh_insert_session_connection on session_connection;
  drop function wh_insert_session_connection();

  --  If the connected_time_range is null, it means the connection is authorized but not connected.
  --  If the upper value of connected_time_range is > now() (upper range is infinity) then the state is connected.
  --  If the upper value of connected_time_range is <= now() then the connection is closed.
  alter table session_connection
    add column connected_time_range tstzrange;

  -- Migrate existing data from session_connection_state to session_connection
   update session_connection
      set connected_time_range = (select tstzrange(min(start_time), max(start_time))
                                    from session_connection_state
                                   where session_connection_state.connection_id = session_connection.public_id
                                group by connection_id );

  drop table session_connection_state;
  drop table session_connection_state_enm;

  -- Insert on session_connection creates the connection entry, leaving the connected_time_range to null, indicating the connection is authorized
  -- "Connected" is handled by the function ConnectConnection, which sets the connected_time_range lower bound to now() and upper bound to infinity
  -- "Closed" is handled by the trigger function, update_connected_time_range_on_closed_reason, which sets the connected_time_range upper bound to now()
  -- State transitions are guarded by the trigger function, check_connection_state_transition, which ensures that the state transitions are valid
  create function check_connection_state_transition() returns trigger
  as $$
    begin
    -- If old state was authorized, allow transition to connected or closed
    if old.connected_time_range is null then
      return new;
    end if;

    -- If old state was closed, no transitions are allowed
    if upper(old.connected_time_range) < 'infinity' and old.connected_time_range != new.connected_time_range then
      raise exception 'Invalid state transition from closed';
    end if;

    -- If old state was connected, allow transition to closed
    if upper(old.connected_time_range) =  'infinity'                      and
       upper(new.connected_time_range) != 'infinity'                      and
       lower(old.connected_time_range) =  lower(new.connected_time_range) then
      return new;
    else
      raise exception 'Invalid state transition from connected';
    end if;

    return new;
    end;
  $$ language plpgsql;

  create trigger check_connection_state_transition before update of connected_time_range on session_connection
    for each row execute procedure check_connection_state_transition();

  create function update_connected_time_range_on_closed_reason() returns trigger
  as $$
    begin
      if new.closed_reason is not null then
          if old.connected_time_range is null or upper(old.connected_time_range) = 'infinity'::timestamptz then
             new.connected_time_range = tstzrange(lower(old.connected_time_range), now(), '[]');
          end if;
      end if;
    return new;
    end;
  $$ language plpgsql;

  create trigger update_connected_time_range_closed_reason before update of closed_reason on session_connection
    for each row execute procedure update_connected_time_range_on_closed_reason();

  create function update_session_state_on_termination_reason() returns trigger
    as $$
  begin
    if new.termination_reason is not null then
      perform
         from session_connection
        where session_id                  = new.public_id
          and upper(connected_time_range) = 'infinity'::timestamptz;
        if found then
            raise 'session %s has open connections', new.public_id;
        end if;
      -- check to see if there's a terminated state already, before inserting a
      -- new one.
      perform
         from session_state ss
        where ss.session_id = new.public_id and
                   ss.state = 'terminated';
      if found then
        return new;
      end if;
      insert into session_state (session_id,    state)
           values               (new.public_id, 'terminated');
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger update_session_state_on_termination_reason after update of termination_reason on session
    for each row execute procedure update_session_state_on_termination_reason();

  create function wh_insert_session_connection() returns trigger
    as $$
    declare
  new_row wh_session_connection_accumulating_fact%rowtype;
  begin
    with
      authorized_timestamp (date_dim_key, time_dim_key, ts) as (
        select wh_date_key(create_time), wh_time_key(create_time), create_time
          from session_connection
         where public_id = new.public_id
           and connected_time_range is null
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

  create function wh_insert_session_connection_state() returns trigger
  as $$
    declare
               state text;
            date_col text;
            time_col text;
              ts_col text;
                   q text;
      connection_row wh_session_connection_accumulating_fact%rowtype;
    begin
      if new.connected_time_range is null then
        -- Indicates authorized connection. The update statement in this
        -- trigger will fail for the authorized state because the row for the
        -- session connection has not yet been inserted into the
        -- wh_session_connection_accumulating_fact table.
        return null;
      end if;

      if upper(new.connected_time_range) = 'infinity'::timestamptz then
            update wh_session_connection_accumulating_fact
               set (connection_connected_date_key,
                    connection_connected_time_key,
                    connection_connected_time) = (select wh_date_key(new.update_time),
                                                         wh_time_key(new.update_time),
                                                         new.update_time::timestamptz)
              where connection_id = new.public_id;
      else
             update wh_session_connection_accumulating_fact
                set (connection_closed_date_key,
                     connection_closed_time_key,
                     connection_closed_time) = (select wh_date_key(new.update_time),
                                                       wh_time_key(new.update_time),
                                                       new.update_time::timestamptz)
               where connection_id = new.public_id;
      end if;

      return null;
    end;
  $$ language plpgsql;

  create trigger wh_insert_session_connection_state after update of connected_time_range on session_connection
    for each row execute function wh_insert_session_connection_state();

  create view session_connection_with_status_view as
       select public_id,
              session_id,
              client_tcp_address,
              client_tcp_port,
              endpoint_tcp_address,
              endpoint_tcp_port,
              bytes_up,
              bytes_down,
              closed_reason,
              version,
              create_time,
              update_time,
              user_client_ip,
              worker_id,
              case
                  when connected_time_range is null        then 'authorized'
                  when upper(connected_time_range) > now() then 'connected'
                  else                                          'closed'
              end as status
       from session_connection;

  create index connected_time_range_idx on session_connection (connected_time_range);

  create index connected_time_range_upper_idx on session_connection (upper(connected_time_range));

commit;