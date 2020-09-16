begin;

/*

             ┌─────────────────┐               ┌─────────────────┐   ┌─────────────────┐
             │  iam_scope_org  │               │    iam_user     │   │   auth_token    │
             ├─────────────────┤               ├─────────────────┤   ├─────────────────┤
             │ public_id  (pk) │               │ public_id (pk)  │   │ public_id  (pk) │
             │                 │               │                 │   │                 │
             └─────────────────┘               └─────────────────┘   └─────────────────┘
                 ▲fk7 ┼                            ▲fk1 ┼                ▲fk6 ┼
                      ┼                                 ┼                     ┼
                      ├─────────────────────────────────┴─────────────────────┘
                      │
                      ○
                     ╱│╲
        ┌──────────────────────────┐          ┌─────────────────┐   ┌─────────────────┐
        │         session          │╲  fk3▶   │     server      │   │     target      │
        ├──────────────────────────┤─○──────○┼├─────────────────┤   ├─────────────────┤
        │ public_id          (pk)  │╱         │ private_id (pk) │   │ public_id  (pk) │
        │ user_id            (fk1) │          │ type       (pk) │   │                 │
        │ host_id            (fk2) │          └─────────────────┘   └─────────────────┘
        │ server_id          (fk3) │                                    ▲fk4 ┼
        │ server_type        (fk3) │╲                                        ┼
        │ target_id          (fk4) │─○─────────────────┬─────────────────────┤
        │ host_set_id        (fk5) │╱                  ┼                     ┼
        │ auth_token_id      (fk6) │              ▼fk5 ┼                ▼fk2 ┼
        │ scope_id           (fk7) │          ┌─────────────────┐   ┌─────────────────┐
        │ termination_reason (fk8) │          │    host_set     │   │      host       │
        └──────────────────────────┘          ├─────────────────┤   ├─────────────────┤
                 ▲fk1 ┼           ╲│╱         │ public_id  (pk) │   │ public_id  (pk) │
                      ┼            ○          │                 │   │                 │
                      │            │          └─────────────────┘   └─────────────────┘
                      │            │
                      └─┐          │
                        │          │            ┌───────────────────────────────┐
                        │          │            │session_termination_reason_enm │
                        │          │     fk8▶   ├───────────────────────────────┤
                        ┼          └──────────○┼│ name                          │
                       ╱│╲                      └───────────────────────────────┘
  ┌──────────────────────────────────────────┐
  │              session_state               │
  ├──────────────────────────────────────────┤┼○┐
  │ session_id        (pk,fk1,fk2,unq1,unq2) │  │◀fk2
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
        │       session_state_enm       │
        ├───────────────────────────────┤
        │ name                          │
        └───────────────────────────────┘

*/

  create table session_termination_reason_enm (
    name text primary key
      check (
        name in (
          'unknown',
          'timed out',
          'closed by end-user',
          'terminated',
          'network error',
          'system error'
        )
      )
  );

  insert into session_termination_reason_enm (name)
  values
    ('unknown'),
    ('timed out'),
    ('closed by end-user'),
    ('terminated'),
    ('network error'),
    ('system error');

  create table session (
    public_id wt_public_id primary key,
    -- the user of the session
    user_id text -- fk1
      -- not using the wt_user_id domain type because it is marked 'not null'
      references iam_user (public_id)
      on delete set null
      on update cascade,
    -- the host the user is connected to via this session
    host_id wt_public_id -- fk2
      references host (public_id)
      on delete set null
      on update cascade,
    -- the worker proxying the connection between the user and the host
    server_id text, -- fk3
    server_type text,-- fk3
    foreign key (server_id, server_type)
      references server (private_id, type)
      on delete set null
      on update cascade,
    -- the target the host was chosen from and the user was authorized to
    -- connect to
    target_id wt_public_id -- fk4
      references target (public_id)
      on delete set null
      on update cascade,
    -- the host set the host was chosen from and the user was authorized to
    -- connect to via the target
    host_set_id wt_public_id -- fk5
      references host_set (public_id)
      on delete set null
      on update cascade,
    -- the auth token of the user when this session was created
    auth_token_id wt_public_id -- fk6
      references auth_token (public_id)
      on delete set null
      on update cascade,
    -- the project which owns this session
    scope_id wt_scope_id -- fk7
      references iam_scope_project (scope_id)
      on delete set null
      on update cascade,
    -- Certificate to use when connecting (or if using custom certs, to
	  -- serve as the "login"). Raw DER bytes.  
    certificate bytea not null,
    -- after this time the connection will be expired, e.g. forcefully terminated
    expiration_time wt_timestamp, -- maybe null
    -- trust of first use token 
    tofu_token bytea, -- will be null when session is first created
    -- the reason this session ended (null until terminated)
     -- TODO: Make key_id a foreign key once we have DEKs
    key_id text, -- will be null on insert
      -- references kms_database_key_version(private_id) 
      -- on delete restrict
      -- on update cascade,
    termination_reason text -- fk8
      references session_termination_reason_enm (name)
      on delete restrict
      on update cascade,
    version wt_version,
    create_time wt_timestamp,
    update_time wt_timestamp
  );

  create trigger 
    immutable_columns
  before
  update on session
    for each row execute procedure immutable_columns('public_id', 'certificate', 'expiration_time', 'create_time');
  
  create trigger 
    update_version_column 
  after update on session
    for each row execute procedure update_version_column();
    
  create trigger 
    update_time_column 
  before update on session 
    for each row execute procedure update_time_column();
    
  create trigger 
    default_create_time_column
  before
  insert on session
    for each row execute procedure default_create_time();

  create or replace function
    insert_session()
    returns trigger
  as $$
  begin
    case 
      when new.user_id is null then
        raise exception 'user_id is null';
      when new.host_id is null then
        raise exception 'host_id is null';
      when new.target_id is null then
        raise exception 'target_id is null';
      when new.host_set_id is null then
        raise exception 'host_set_id is null';
      when new.auth_token_id is null then
        raise exception 'auth_token_id is null';
      when new.scope_id is null then
        raise exception 'scope_id is null';
    else
    end case;
    return new;
  end;
  $$ language plpgsql;

  create trigger 
    insert_session
  before insert on session
    for each row execute procedure insert_session();

  create or replace function 
    insert_new_session_state()
    returns trigger
  as $$
  begin
    insert into session_state (session_id, state)
    values
      (new.public_id, 'pending');
    return new;
  end;
  $$ language plpgsql;

  create trigger 
    insert_new_session_state
  after insert on session
    for each row execute procedure insert_new_session_state();

  -- update_connection_state_on_closed_reason() is used in an update insert trigger on the
  -- session_connection table.  it will valiadate that all the session's
  -- connections are closed, and then insert a state of "closed" in
  -- session_connection_state for the closed session connection. 
  create or replace function 
    update_session_state_on_termination_reason()
    returns trigger
  as $$
  begin
    if new.termination_reason is not null then
      perform from
        session_connection sc,
        session_connection_state scs
      where
        sc.public_id = scs.connection_id and 
        scs.state != 'closed' and
        sc.session_id = new.public_id;
      if found then 
        raise 'session %s has existing open connections', new.public_id;
      end if;
      insert into session_state (session_id, state)
      values
        (new.public_id, 'terminated');
      end if;
      return new;
  end;
  $$ language plpgsql;


  create trigger 
    update_session_state_on_termination_reason
  after update of termination_reason on session
    for each row execute procedure update_session_state_on_termination_reason();
 

  create table session_state_enm (
    name text primary key
      check (
        name in ('pending', 'active', 'canceling', 'terminated')
      )
  );

  insert into session_state_enm (name)
  values
    ('pending'),
    ('active'),
    ('canceling'),
    ('terminated');

/*


                                              ┌────────────────┐
         start                                │                │
           .                                  │   Canceling    │
          (●)                           ┌────▶│                │─────┐
           '                            │     │                │     │
           │                            │     └────────────────┘     │
           │                            │                            │
           ▼                            │                            ▼
  ┌────────────────┐           ┌────────────────┐           ┌────────────────┐
  │                │           │                │           │                │
  │    Pending     │           │     Active     │           │   Terminated   │
  │                │──────────▶│                │──────────▶│                │
  │                │           │                │           │                │
  └────────────────┘           └────────────────┘           └────────────────┘
           │                                                         │
           │                                                         │
           │                                                         │
           │                                                         │
           └──────────────────────▶  ◉ End  ◀────────────────────────┘

*/

  -- Design influenced by:
  -- Joe Celko's SQL for Smarties: Advanced SQL Programming, 5th edition
  -- Chapter 12, p270
  create table session_state (
    session_id wt_public_id not null -- fk1, fk2
      references session (public_id)
      on delete cascade
      on update cascade,
    state text not null -- fk3
      references session_state_enm(name)
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
    primary key (session_id, start_time),
    unique (session_id, previous_end_time), -- null means first state
    unique (session_id, end_time), -- one null current state
    foreign key (session_id, previous_end_time) -- self-reference
      references session_state (session_id, end_time)
  );


  create trigger 
    immutable_columns
  before
  update on session_state
    for each row execute procedure immutable_columns('session_id', 'start_time', 'previous_end_time');
    
  create or replace function
    insert_session_state()
    returns trigger
  as $$
  begin

    update session_state
       set end_time = now()
     where session_id = new.session_id
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


  create trigger insert_session_state before insert on session_state
    for each row execute procedure insert_session_state();


commit;
