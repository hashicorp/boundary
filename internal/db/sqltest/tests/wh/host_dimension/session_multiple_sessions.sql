-- session_multiple_sessions tests the wh_host_dimesion when
-- multiple sessions are created using the same user and auth method.
begin;
  select plan(6);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new host dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-plghs' , 'h_____wb__02-plgh' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's1____walter');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  -- should not result in a new host dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-plghs' , 'h_____wb__02-plgh' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's2____walter');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * different user
  --  * same auth
  --  * same host
  -- should not result in a new host dimension
  insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-plghs' , 'h_____wb__02-plgh' , 'u_____warren' , 'tok___warren' , 'abc'::bytea , 'ep1'    , 's3____walter');

  select is(count(*), 1::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  --  * host has a different set of addresses
  insert into host_dns_name
  (host_id, name)
  values
    ('h_____wb__02-plgh', 'new.big.widget');

  -- should result in a new host dimension
  insert into session
  ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-plghs' , 'h_____wb__02-plgh' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's4____walter');

  select is(count(*), 2::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  --  * host has a different set of addresses with ipv6
  insert into host_ip_address
  (host_id, address)
  values
    ('h_____wb__02-plgh', 'fe80::beef:1111:2222:333');

  -- should result in a new host dimension
  insert into session
  ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
  values
    ('p____bwidget' , 't_________wb' , 's___1wb-plghs' , 'h_____wb__02-plgh' , 'u_____walter' , 'tok___walter' , 'abc'::bytea , 'ep1'    , 's5____walter');

  select is(count(*), 3::bigint) from wh_host_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;

