-- wh_user_dimension tests that when a session is inserted,
-- the wh_user_dimension is populated with the user information.
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'auth', 'hosts', 'targets');

  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(user_id,          'u_____walter') from wh_user_dimension;
  select is(user_name,        'Walter')       from wh_user_dimension;
  select is(user_description, 'None')         from wh_user_dimension;

  select * from finish();
rollback;
