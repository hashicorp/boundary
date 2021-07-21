-- session_multiple_sessions tests the wh_user_dimesion when
-- multiple sessions are created using the same user and auth method.
begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_user_dimension;

  -- insert first session, should result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(count(*), 1::bigint) from wh_user_dimension;

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  -- should not result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's2____walter');

  select is(count(*), 1::bigint) from wh_user_dimension;

  -- another session with:
  --  * same user
  --  * same auth
  --  * different host
  -- should not result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__02' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's3____walter');

  select is(count(*), 1::bigint) from wh_user_dimension;

  select * from finish();
rollback;
