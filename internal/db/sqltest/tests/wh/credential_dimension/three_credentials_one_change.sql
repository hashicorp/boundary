-- three_credentials_one_change tests that:
--  when a session with three credentials is created
--  three wh_credential_dimensions are created
--  then when one of the credential libraries is updated
--  and a new session is created
--  only one of the wh_credential_dimensions is updated
begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert session and session_credential_dynamic, should result in a three new credential dimensions
  insert into session
    ( project_id,     target_id,      host_set_id,    host_id,        user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 's___1wb-sths', 'h_____wb__01', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's1____walter');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s1____walter', 'vl______wvl1', null,           'brokered'),
    ('s1____walter', 'vl______wvl2', null,           'brokered'),
    ('s1____walter', 'vl______wvl3', null,           'brokered');

  select is(count(*), 3::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  update credential_vault_library set vault_path = '/secrets/tcp/user' where public_id = 'vl______wvl2';

  insert into session
    ( project_id,     target_id,      host_set_id,    host_id,        user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 's___1wb-sths', 'h_____wb__01', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's2____walter');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s2____walter', 'vl______wvl1', null,           'brokered'),
    ('s2____walter', 'vl______wvl2', null,           'brokered'),
    ('s2____walter', 'vl______wvl3', null,           'brokered');

  select is(count(*), 4::bigint) from wh_credential_dimension where organization_id = 'o_____widget';
  select is(count(*), 3::bigint) from wh_credential_dimension where organization_id = 'o_____widget' and current_row_indicator = 'Current';

  select * from finish();
rollback;

