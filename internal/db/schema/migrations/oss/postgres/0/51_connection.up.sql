-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

/*

               ┌────────────────┐
               │    session     │
               ├────────────────┤
               │ public_id (pk) │
               │                │
               │                │
               └────────────────┘
                   ▲fk1 ┼
                        ┼
                        │
                        │
                        ┼
                       ╱│╲                  ┌──────────────────────────────────────┐
            ┌───────────────────────┐       │ session_connection_closed_reason_enm │
            │  session_connection   │╲ fk2▶ ├──────────────────────────────────────┤
            ├───────────────────────┤─○───○┼│ name                                 │
            │ public_id     (pk)    │╱      └──────────────────────────────────────┘
            │ session_id    (fk1)   │
            │ closed_reason (fk2)   │
            └───────────────────────┘
                   ▲fk1 ┼
                        ┼
                        │
                        │
                        ┼
                       ╱│╲
  ┌──────────────────────────────────────────┐
  │         session_connection_state         │
  ├──────────────────────────────────────────┤┼○┐
  │ connection_id     (pk,fk1,fk2,unq1,unq2) │  │◀fk2
  │ state             (fk3)                  │  │
  │ previous_end_time (fk2,unq1)             │┼○┘
  │ start_time        (pk)                   │
  │ end_time          (unq2)                 │
  └──────────────────────────────────────────┘
                       ╲│╱
                        ○
                        │
                        │
                        ┼
                  ▼fk3  ┼
        ┌───────────────────────────────┐
        │ session_connection_state_enm  │
        ├───────────────────────────────┤
        │ name                          │
        └───────────────────────────────┘

*/

  create table session_connection_closed_reason_enm (
    name text primary key
      constraint only_predefined_session_connection_closed_reasons_allowed
      check (
        name in (
          'unknown',
          'timed out',
          'closed by end-user',
          'canceled',
          'network error',
          'system error'
        )
      )
  );

  insert into session_connection_closed_reason_enm (name)
  values
    ('unknown'),
    ('timed out'),
    ('closed by end-user'),
    ('canceled'),
    ('network error'),
    ('system error');

  -- A session connection is one connection proxied by a worker from a client to
  -- a endpoint for a session. The client initiates the connection to the worker
  -- and the worker initiates the connection to the endpoint.
  -- A session can have zero or more session connections.
  -- Note: Updated to add server_id, server_type in 801
  create table session_connection (
    public_id wt_public_id primary key,
    session_id wt_public_id not null
      references session (public_id)
      on delete cascade
      on update cascade,
    -- the client_tcp_address is the network address of the client which initiated
    -- the connection to a worker
    client_tcp_address inet,  -- maybe null on insert
    -- the client_tcp_port is the network port at the address of the client the
    -- worker proxied a connection for the user
    client_tcp_port integer  -- maybe null on insert
      constraint client_tcp_port_must_be_greater_than_0
      check(client_tcp_port > 0)
      constraint client_tcp_port_must_less_than_or_equal_to_65535
      check(client_tcp_port <= 65535),
    -- the endpoint_tcp_address is the network address of the endpoint which the
    -- worker initiated the connection to, for the user
    endpoint_tcp_address inet, -- maybe be null on insert
    -- the endpoint_tcp_port is the network port at the address of the endpoint the
    -- worker proxied a connection to, for the user
    endpoint_tcp_port integer -- maybe null on insert
      constraint endpoint_tcp_port_must_be_greater_than_0
      check(endpoint_tcp_port > 0)
      constraint endpoint_tcp_port_must_less_than_or_equal_to_65535
      check(endpoint_tcp_port <= 65535),
    -- the total number of bytes received by the worker from the client and sent
    -- to the endpoint for this connection
    bytes_up bigint -- can be null
      constraint bytes_up_must_be_null_or_a_non_negative_number
      check (
        bytes_up is null
        or
        bytes_up >= 0
      ),
    -- the total number of bytes received by the worker from the endpoint and sent
    -- to the client for this connection
    bytes_down bigint -- can be null
      constraint bytes_down_must_be_null_or_a_non_negative_number
      check (
        bytes_down is null
        or
        bytes_down >= 0
      ),
    closed_reason text
      references session_connection_closed_reason_enm (name)
      on delete restrict
      on update cascade,
    version wt_version,
    create_time wt_timestamp,
    update_time wt_timestamp
  );

  create trigger immutable_columns before update on session_connection
    for each row execute procedure immutable_columns('public_id', 'session_id', 'create_time');

  create trigger update_version_column after update on session_connection
    for each row execute procedure update_version_column();
    
  create trigger update_time_column before update on session_connection
    for each row execute procedure update_time_column();
    
  create trigger default_create_time_column before insert on session_connection
    for each row execute procedure default_create_time();

  -- Removed in 90/01_remove_session_connection_state.up.sql
  -- insert_new_connection_state() is used in an after insert trigger on the
  -- session_connection table.  it will insert a state of "authorized" in
  -- session_connection_state for the new session connection. 
  create or replace function insert_new_connection_state() returns trigger
  as $$
  begin
    insert into session_connection_state (connection_id, state)
    values
      (new.public_id, 'authorized');
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_new_connection_state after insert on session_connection
    for each row execute procedure insert_new_connection_state();

-- Replaced in 27/01_disable_terminate_session.up.sql
  -- update_connection_state_on_closed_reason() is used in an update trigger on the
  -- session_connection table.  it will insert a state of "closed" in
  -- session_connection_state for the closed session connection. 
  create or replace function update_connection_state_on_closed_reason() returns trigger
  as $$
  begin
    if new.closed_reason is not null then
      -- check to see if there's a closed state already, before inserting a
      -- new one.
      perform from
        session_connection_state cs
      where
        cs.connection_id = new.public_id and 
        cs.state = 'closed';
      if not found then 
        insert into session_connection_state (connection_id, state)
        values
          (new.public_id, 'closed');
      end if;
      -- whenever we close a connection, we want to terminate the session if
      -- possible.  
      perform terminate_session_if_possible(new.session_id);
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger update_connection_state_on_closed_reason after update of closed_reason on session_connection
    for each row execute procedure update_connection_state_on_closed_reason();

  create table session_connection_state_enm (
    name text primary key
      constraint only_predefined_session_connection_states_allowed
      check (
        name in ('authorized', 'connected', 'closed')
      )
  );

  insert into session_connection_state_enm (name)
  values
    ('authorized'),
    ('connected'),
    ('closed');

  create table session_connection_state (
    connection_id wt_public_id not null
      references session_connection (public_id)
      on delete cascade
      on update cascade,
    state text not null
      references session_connection_state_enm(name)
      on delete restrict
      on update cascade,
    previous_end_time timestamp with time zone, -- fk2 -- null means first state
    start_time timestamp with time zone default current_timestamp not null,
      constraint previous_end_time_and_start_time_in_sequence
        check (previous_end_time <= start_time),
    end_time timestamp with time zone, -- null means unfinished current state
      constraint start_and_end_times_in_sequence
        check (start_time <= end_time),
      constraint end_times_in_sequence
        check (previous_end_time <> end_time),
    primary key (connection_id, start_time),
    unique (connection_id, previous_end_time), -- null means first state
    unique (connection_id, end_time), -- one null current state
    foreign key (connection_id, previous_end_time) -- self-reference
      references session_connection_state (connection_id, end_time)
  );

  create trigger immutable_columns before update on session_connection_state
    for each row execute procedure immutable_columns('connection_id', 'state', 'start_time', 'previous_end_time');

  create or replace function insert_session_connection_state() returns trigger
  as $$
  begin

    update session_connection_state
       set end_time = now()
     where connection_id = new.connection_id
       and end_time is null;

    if not found then
      new.previous_end_time = null;
      new.start_time = now();
      new.end_time = null;
      return new;
    end if;

    new.previous_end_time = now();
    new.start_time = now();
    new.end_time = null;
    return new;

  end;
  $$ language plpgsql;

  create trigger insert_session_connection_state before insert on session_connection_state
    for each row execute procedure insert_session_connection_state();

-- Removed in 27/01_disable_terminate_session.up.sql
-- terminate_session_if_possible takes a session id and terminates the session
-- if the following conditions are met:
--    * the session is expired and all its connections are closed.
--    * the session is canceling and all its connections are closed
--    * the session has exhausted its connection limit and all its connections
--      are closed.  
--
--      Note: this function should align closely with the domain function
--      TerminateCompletedSessions 
create or replace function terminate_session_if_possible(terminate_session_id text) returns void
  as $$
  begin 
    -- is terminate_session_id in a canceling state
    with canceling_session(session_id) as
    (
      select 
        session_id
      from
        session_state ss
      where 
        ss.session_id = terminate_session_id and
        ss.state = 'canceling' and 
        ss.end_time is null
    )
    update session us
      set termination_reason = 
      case 
        -- timed out sessions
        when now() > us.expiration_time then 'timed out'
        -- canceling sessions
        when us.public_id in(
          select 
            session_id 
          from 
            canceling_session cs 
          where
            us.public_id = cs.session_id
          ) then 'canceled' 
        -- default: session connection limit reached.
        else 'connection limit'
      end
    where
      -- limit update to just the terminating_session_id
      us.public_id = terminate_session_id and
      termination_reason is null and
      -- session expired or connection limit reached
      (
        -- expired sessions...
        now() > us.expiration_time or 
        -- connection limit reached...
        (
          -- handle unlimited connections...
          connection_limit != -1 and
          (
            select count (*) 
              from session_connection sc 
            where 
              sc.session_id = us.public_id
          ) >= connection_limit
        ) or 
        -- canceled sessions
        us.public_id in (
          select 
            session_id
          from
            canceling_session cs
          where 
            us.public_id = cs.session_id 
        )
      ) and 
      -- make sure there are no existing connections
      us.public_id not in (
        select 
          session_id 
        from 
            session_connection
          where public_id in (
          select 
            connection_id
          from 
            session_connection_state
          where 
            state != 'closed' and
            end_time is null
        )
    );
 end;
  $$ language plpgsql;

commit;
