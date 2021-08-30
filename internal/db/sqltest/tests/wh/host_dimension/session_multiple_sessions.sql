-- session_multiple_sessions tests the wh_host_dimesion when
-- multiple sessions are created using the same user and auth method.
begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  -- should not result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's2____walter');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * different user
  --  * same auth
  --  * same host
  -- should not result in a new user dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____warren' , 'tok___warren' , 'abc'::bytea , 'ep1'    , 's3____walter');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;

