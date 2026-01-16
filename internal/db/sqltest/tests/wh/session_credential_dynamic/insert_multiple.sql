-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

--- insert_multiple tests inserting multiple session_credential_dynamic as a single statement
begin;
  select plan(6);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  select is(count(*), 0::bigint) from wh_credential_dimension        where organization_id      =  'o_____widget';
  select is(count(*), 2::bigint) from wh_credential_group_membership where credential_group_key != 'no credentials' and credential_group_key != 'Unknown';
  select is(count(*), 1::bigint) from wh_credential_group            where key                  != 'no credentials' and key                  != 'Unknown';

  --- multiple single credentials
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
    ('s1____walter', 'vl______wvl1', null,           'brokered'),
    ('s1____walter', 'vl______wvl2', null,           'brokered'),
    ('s1____walter', 'vl______wvl3', null,           'brokered'),
    ('s1____walter', 'vl______wvl3', null,           'injected_application');

  select is(count(*), 4::bigint) from wh_credential_dimension        where organization_id      =  'o_____widget';
  select is(count(*), 6::bigint) from wh_credential_group_membership where credential_group_key != 'no credentials' and credential_group_key != 'Unknown';
  select is(count(*), 2::bigint) from wh_credential_group            where key                  != 'no credentials' and key                  != 'Unknown';

  select * from finish();
rollback;
