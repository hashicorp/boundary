-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  insert into target_rdp
    (project_id, public_id, name)
  values
    ('p____bwidget', 'trdp______wb', 'Big Widget RDP Target');

  insert into target_host_set
    (project_id, target_id, host_set_id)
  values
    ('p____bwidget', 'trdp______wb', 's___1wb-sths');

  insert into target_credential_library
    (project_id,     target_id,      credential_library_id, credential_purpose)
  values
    ('p____bwidget', 'trdp______wb', 'vl______wvl1',        'brokered');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert session, should result in a new credentials dimension with an rdp target type
  insert into session
    ( project_id,      target_id,     user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget',  'trdp______wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,     library_id,     credential_id,  credential_purpose)
  values
    ('s1____walter',  'vl______wvl1', null,           'brokered');
  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget' and target_type = 'rdp target';
rollback;
