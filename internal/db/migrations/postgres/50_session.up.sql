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
        │ set_id             (fk5) │╱                  ┼                     ┼
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
    user_id wt_user_id -- fk1
      not null
      references iam_user (public_id)
      on delete cascade
      on update cascade,
    -- the host the user is connected to via this session
    host_id wt_public_id -- fk2
      not null
      references host (public_id)
      on delete cascade
      on update cascade,
    -- the worker proxying the connection between the user and the host
    server_id text not null, -- fk3
    server_type text not null,-- fk3
    foreign key (server_id, server_type)
      references server (private_id, type)
      on delete cascade
      on update cascade,
    -- the target the host was chosen from and the user was authorized to
    -- connect to
    target_id wt_public_id -- fk4
      not null
      references target (public_id)
      on delete cascade
      on update cascade,
    -- the host set the host was chosen from and the user was authorized to
    -- connect to via the target
    set_id wt_public_id -- fk5
      not null
      references host_set (public_id)
      on delete cascade
      on update cascade,
    -- the auth token of the user when this session was created
    auth_token_id wt_public_id -- fk6
      not null
      references auth_token (public_id)
      on delete cascade
      on update cascade,
    -- the organization which owns this session
    scope_id wt_scope_id -- fk7
      not null
      references iam_scope_org (scope_id)
      on delete cascade
      on update cascade,
    -- the reason this session ended (null until terminated)
    termination_reason text -- fk8
      references session_termination_reason_enm (name)
      on delete restrict
      on update cascade,
    -- the network address of the host the worker proxied a connection to for
    -- the user
    address text
      not null
      check(
        length(trim(address)) > 7
        and
        length(trim(address)) < 256
      ),
    -- the network port at the address of the host the worker proxied a
    -- connection to for the user
    port integer
      not null
      check(
        port > 0
        and
        port <= 65535
      ),
    -- the total number of bytes received by the worker from the user and sent
    -- to the host for this session
    bytes_up bigint -- can be null
      check (
        bytes_up is null
        or
        bytes_up >= 0
      ),
    -- the total number of bytes received by the worker from the host and sent
    -- to the user for this session
    bytes_down bigint -- can be null
      check (
        bytes_down is null
        or
        bytes_down >= 0
      )
  );

  create table session_state_enm (
    name text primary key
      check (
        name in ('pending', 'connected', 'closed')
      )
  );

  insert into session_state_enm (name)
  values
    ('pending'),
    ('connected'),
    ('closed');

/*

          (●) Start
           │
           │
           │
           ▼
  ┌────────────────┐           ┌────────────────┐           ┌────────────────┐
  │                │           │                │           │                │
  │    Pending     │           │   Connected    │           │     Closed     │
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

commit;
