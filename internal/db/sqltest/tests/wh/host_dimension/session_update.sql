-- session_update tests the wh_host_dimesion when
-- a session is inserted and then updated.
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new host dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- update session, should not impact wh_host_dimension
  update session set
    version = 2
  where
    public_id = 's1____walter';

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;
