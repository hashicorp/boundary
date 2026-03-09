-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

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
      constraint only_predefined_session_termination_reasons_allowed
      check (
        name in (
          'unknown',
          'timed out',
          'closed by end-user',
          'terminated',
          'network error',
          'system error',
          'connection limit',
          'canceled'
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
    ('system error'),
    ('connection limit'),
    ('canceled');

-- Note: here, and in the session_connection table, we should add a trigger
-- ensuring that if server_id goes to null, we mark connections as closed. See
-- https://hashicorp.atlassian.net/browse/ICU-1495
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
    -- limit on number of session connections allowed.  default of 0 equals no limit
    connection_limit int not null default 1
      constraint connection_limit_must_be_greater_than_0_or_negative_1
      check(connection_limit > 0 or connection_limit = -1), 
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
    update_time wt_timestamp,
    endpoint text -- not part of the warehouse, used to send info to the worker
  );

  -- Replaced in 100 to add worker_filter
  create trigger immutable_columns before update on session
    for each row execute procedure immutable_columns('public_id', 'certificate', 'expiration_time', 'connection_limit', 'create_time', 'endpoint');
  
  -- session table has some cascades of FK to null, so we need to be careful
  -- which columns trigger an update of the version column
  create trigger update_version_column after update of version, termination_reason, key_id, tofu_token, server_id, server_type on session
    for each row execute procedure update_version_column();
    
  create trigger update_time_column before update on session
    for each row execute procedure update_time_column();
    
  create trigger default_create_time_column before insert on session
    for each row execute procedure default_create_time();

  create or replace function insert_session() returns trigger
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
      when new.endpoint is null then
        raise exception 'endpoint is null';
    else
    end case;
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_session before insert on session
    for each row execute procedure insert_session();

  create or replace function insert_new_session_state() returns trigger
  as $$
  begin
    insert into session_state (session_id, state)
    values
      (new.public_id, 'pending');
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_new_session_state after insert on session
    for each row execute procedure insert_new_session_state();

  -- Updated in 90/01_remove_session_connection_state
  -- update_connection_state_on_closed_reason() is used in an update insert trigger on the
  -- session_connection table.  it will valiadate that all the session's
  -- connections are closed, and then insert a state of "closed" in
  -- session_connection_state for the closed session connection. 
  create or replace function update_session_state_on_termination_reason() returns trigger
  as $$
  begin
    if new.termination_reason is not null then
      perform  from 
        session
      where 
        public_id = new.public_id and 
        public_id not in (
            select session_id 
              from session_connection
            where
              public_id in (
                select connection_id
                  from session_connection_state
                where 
                  state != 'closed' and 
                  end_time is null
              )
        );
      if not found then 
        raise 'session %s has open connections', new.public_id;
      end if;

      -- check to see if there's a terminated state already, before inserting a
      -- new one.
      perform from
        session_state ss
      where
        ss.session_id = new.public_id and 
        ss.state = 'terminated';
      if found then 
        return new;
      end if;

      insert into session_state (session_id, state)
      values
        (new.public_id, 'terminated');
      end if;
      return new;
  end;
  $$ language plpgsql;

  create trigger update_session_state_on_termination_reason after update of termination_reason on session
    for each row execute procedure update_session_state_on_termination_reason();

  -- Updated in 29/01_cancel_session_null_fkey
  -- cancel_session will insert a cancel state for the session, if there's isn't
  -- a canceled state already.  It's used by cancel_session_with_null_fk.
  create or replace function cancel_session(in sessionId text) returns void
  as $$
  declare
    rows_affected numeric;
  begin 
    insert into session_state(session_id, state) 
    select 
	    sessionId::text, 'canceling' 
    from
      session s
    where 
      s.public_id = sessionId::text and
      s.public_id not in (
        select 
          session_id 
        from 
          session_state 
        where 
          session_id = sessionId::text and 
          state = 'canceling'
      ) limit 1;
      get diagnostics rows_affected = row_count;
      if rows_affected > 1 then
          raise exception 'cancel session: more than one row affected: %', rows_affected; 
      end if;
  end;
  $$ language plpgsql;

  -- cancel_session_with_null_fk is intended to be a before update trigger that
  -- sets the session's state to cancel if a FK is set to null.
  create or replace function cancel_session_with_null_fk() returns trigger
  as $$
  begin
   case 
      when new.user_id is null then
        perform cancel_session(new.public_id);
      when new.host_id is null then
        perform cancel_session(new.public_id);
      when new.target_id is null then
        perform cancel_session(new.public_id);
      when new.host_set_id is null then
        perform cancel_session(new.public_id);
      when new.auth_token_id is null then
        perform cancel_session(new.public_id);
      when new.scope_id is null then
        perform cancel_session(new.public_id);
    end case;
    return new;
  end;
  $$ language plpgsql;

  create trigger cancel_session_with_null_fk before update of user_id, host_id, target_id, host_set_id, auth_token_id, scope_id on session
    for each row execute procedure cancel_session_with_null_fk();

  create table session_state_enm (
    name text primary key
      constraint only_predefined_session_states_allowed
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

  -- Replaced in 92/02_session_state_tstzrange.up.sql
  create trigger immutable_columns before update on session_state
    for each row execute procedure immutable_columns('session_id', 'state', 'start_time', 'previous_end_time');

-- Replaced in 28/02_prior_session_trigger.up.sql
  create or replace function insert_session_state() returns trigger
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

  -- Replaced in 100 to add worker_filter
  create view session_with_state as
  select
    s.public_id,
    s.user_id,
    s.host_id,
    s.server_id,
    s.server_type,
    s.target_id,
    s.host_set_id,
    s.auth_token_id,
    s.scope_id,
    s.certificate,
    s.expiration_time,
    s.connection_limit,
    s.tofu_token,
    s.key_id,
    s.termination_reason,
    s.version,
    s.create_time,
    s.update_time,
    s.endpoint,
    ss.state,
    ss.previous_end_time,
    ss.start_time,
    ss.end_time
  from  
    session s,
    session_state ss
  where 
    s.public_id = ss.session_id;

commit;
