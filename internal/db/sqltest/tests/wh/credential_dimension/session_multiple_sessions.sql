-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_multiple_sessions tests the wh_credential_dimension when
-- multiple sessions are created using.
begin;
  select plan(13);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new credentials dimension
  insert into session
    ( project_id,      target_id,     user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget',  't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,     library_id,     credential_id,  credential_purpose)
  values
    ('s1____walter',  'vl______wvl1', null,           'brokered');
  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- another session with:
  --  * same user
  --  * same auth
  --  * same host
  -- should not result in a new credential dimension
  insert into session
    ( project_id,     target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's2____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s2____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s2____walter', 'vl______wvl1', null,           'brokered');
  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- change the crediential for the target
  update credential_vault_generic_library set vault_path = '/secrets/tcp/admin' where public_id = 'vl______wvl1';

  -- start another session, should result in a new credential dimension
  insert into session
    ( project_id,     target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's3____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s3____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s3____walter', 'vl______wvl1', null,           'brokered');
  select is(count(*), 2::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- start another session, should result in a one new credential dimensions
  insert into session
    ( project_id,      target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget',  't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's4____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s4____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,     library_id,     credential_id,  credential_purpose)
  values
    ('s4____walter',  'vl______wvl1', null,           'brokered'),
    ('s4____walter',  'vl______wvl2', null,           'brokered');
  select is(count(*), 3::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- change the crediential again for the target
  update credential_vault_generic_library set vault_path = '/secrets/tcp/user' where vault_path = '/secrets/tcp/admin';

  -- start another session, should result in a one new credential dimensions since one changed
  insert into session
    ( project_id,      target_id,     user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget',  't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's5____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s5____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,     library_id,     credential_id,  credential_purpose)
  values
    ('s5____walter',  'vl______wvl1', null,           'brokered'),
    ('s5____walter',  'vl______wvl2', null,           'brokered');
  select is(count(*), 4::bigint) from wh_credential_dimension where organization_id = 'o_____widget';
  select is(count(*), 2::bigint) from wh_credential_dimension where organization_id = 'o_____widget' and current_row_indicator = 'Current';

  -- remove all credentials from the target
  -- then test creating a session
  delete from credential_vault_generic_library;
  insert into session
    ( project_id,                  target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget',              't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's6____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s6____walter', 's___1wb-sths', 'h_____wb__01');
  select is(count(*),             4::bigint)        from wh_credential_dimension                 where organization_id = 'o_____widget';
  select is(credential_group_key, 'no credentials') from wh_session_accumulating_fact            where session_id      = 's6____walter';
  insert into session_connection
    (session_id,                  public_id)
  values
    ('s6____walter',              'sc6____walter');
  select is(credential_group_key, 'no credentials') from wh_session_connection_accumulating_fact where session_id      = 's6____walter';

  -- insert into a session for a target that never had any credentials associated with it.
  insert into session
    ( project_id,                  target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget',              't_________ws', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's7____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s7____walter', 's___1ws-sths', 'h_____ws__01');
  select is(count(*),             4::bigint)        from wh_credential_dimension                 where organization_id = 'o_____widget';
  select is(credential_group_key, 'no credentials') from wh_session_accumulating_fact            where session_id      = 's7____walter';
  insert into session_connection
    (session_id,                  public_id)
  values
    ('s7____walter',              'sc7____walter');
  select is(credential_group_key, 'no credentials') from wh_session_connection_accumulating_fact where session_id      = 's7____walter';

  select * from finish();
rollback;
