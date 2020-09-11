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
      check (
        name in (
          'unknown',
          'timed out',
          'closed by end-user',
          'cancelled',
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
    ('cancelled'),
    ('network error'),
    ('system error');

  -- A session connection is one connection proxied by a worker from a client to
  -- a backend for a session. The client initiates the connection to the worker
  -- and the worker initiates the connection to the backend.
  -- A session can have zero or more session connections.
  create table session_connection (
    public_id wt_public_id primary key,
    session_id wt_public_id not null
      references session (public_id)
      on delete cascade
      on update cascade,
    -- the client_address is the network address of the client which initiated
    -- the connection to a worker
    client_address inet not null,
    -- the client_port is the network port at the address of the client the
    -- worker proxied a connection for the user
    client_port integer not null
      check(
        client_port > 0
        and
        client_port <= 65535
      ),
    -- the backend_address is the network address of the backend which the
    -- worker initiated the connection to, for the user
    backend_address inet not null,
    -- the backend_port is the network port at the address of the backend the
    -- worker proxied a connection to, for the user
    backend_port integer not null
      check(
        backend_port > 0
        and
        backend_port <= 65535
      ),
    -- the total number of bytes received by the worker from the client and sent
    -- to the backend for this connection
    bytes_up bigint -- can be null
      check (
        bytes_up is null
        or
        bytes_up >= 0
      ),
    -- the total number of bytes received by the worker from the backend and sent
    -- to the client for this connection
    bytes_down bigint -- can be null
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

  create table session_connection_state_enm (
    name text primary key
      check (
        name in ('connected', 'closed')
      )
  );

  insert into session_connection_state_enm (name)
  values
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


  create or replace function
    insert_session_connection_state()
    returns trigger
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

commit;
