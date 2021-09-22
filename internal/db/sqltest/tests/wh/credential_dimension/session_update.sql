-- session_update tests the wh_credential_dimension when
-- a session is inserted and then updated.
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new user dimension
  insert into session
    ( scope_id,      target_id,      host_set_id,    host_id,        user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 's___1wb-sths', 'h_____wb__01', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's1____walter');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s1____walter', 'vl______wvl1', null,           'application');

  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- update session, should not impact wh_credential_dimension
  update session set
    version = 2
  where
    public_id = 's1____walter';

  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;

