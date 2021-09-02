-- insert tests that a wh_session_connection_accumulating_fact is created when
-- a connection is established.
begin;
  select plan(2);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  select is(count(*), 0::bigint) from wh_session_connection_accumulating_fact where connection_id = 'sc1____walter';

  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  insert into session_connection
    (session_id, public_id)
  values
    ('s1____walter', 'sc1____walter');

  select is(count(*), 1::bigint) from wh_session_connection_accumulating_fact where connection_id = 'sc1____walter';

  select * from finish();
rollback;
