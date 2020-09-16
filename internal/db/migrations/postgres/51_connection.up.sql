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
    -- the client_tcp_address is the network address of the client which initiated
    -- the connection to a worker
    client_tcp_address inet not null,
    -- the client_tcp_port is the network port at the address of the client the
    -- worker proxied a connection for the user
    client_tcp_port integer not null
      check(
        client_tcp_port > 0
        and
        client_tcp_port <= 65535
      ),
    -- the backend_tcp_address is the network address of the backend which the
    -- worker initiated the connection to, for the user
    backend_tcp_address inet not null,
    -- the backend_tcp_port is the network port at the address of the backend the
    -- worker proxied a connection to, for the user
    backend_tcp_port integer not null
      check(
        backend_tcp_port > 0
        and
        backend_tcp_port <= 65535
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

  create trigger 
    immutable_columns
  before
  update on session_connection
    for each row execute procedure immutable_columns('public_id', 'session_id', 'client_tcp_address', 'client_tcp_port', 'backend_tcp_address', 'backend_tcp_port', 'create_time');

  create trigger 
    update_version_column 
  after update on session_connection
    for each row execute procedure update_version_column();
    
  create trigger 
    update_time_column 
  before update on session_connection 
    for each row execute procedure update_time_column();
    
  create trigger 
    default_create_time_column
  before
  insert on session_connection
    for each row execute procedure default_create_time();

  -- insert_new_connection_state() is used in an after insert trigger on the
  -- session_connection table.  it will insert a state of "connected" in
  -- session_connection_state for the new session connection. 
  create or replace function 
    insert_new_connection_state()
    returns trigger
  as $$
  begin
    insert into session_connection_state (connection_id, state)
    values
      (new.public_id, 'connected');
    return new;
  end;
  $$ language plpgsql;

  create trigger 
    insert_new_connection_state
  after insert on session_connection
    for each row execute procedure insert_new_connection_state();

  -- update_connection_state_on_closed_reason() is used in an update insert trigger on the
  -- session_connection table.  it will insert a state of "closed" in
  -- session_connection_state for the closed session connection. 
  create or replace function 
    update_connection_state_on_closed_reason()
    returns trigger
  as $$
  begin
    if new.closed_reason is not null then
      insert into session_connection_state (connection_id, state)
      values
        (new.public_id, 'closed');
      end if;
      return new;
  end;
  $$ language plpgsql;

  create trigger 
    update_connection_state_on_closed_reason
  after update of closed_reason on session_connection
    for each row execute procedure update_connection_state_on_closed_reason();

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

  create trigger 
    immutable_columns
  before
  update on session_connection_state
    for each row execute procedure immutable_columns('connection_id', 'state', 'start_time');

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
