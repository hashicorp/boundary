-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_update tests the wh_credential_dimension when
-- a session is inserted and then updated.
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new user dimension
  insert into session
    ( project_id,     target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s1____walter', 'vl______wvl1', null,           'brokered');

  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- update session, should not impact wh_credential_dimension
  update session set
    version = 2
  where
    public_id = 's1____walter';

  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  select * from finish();
rollback;

