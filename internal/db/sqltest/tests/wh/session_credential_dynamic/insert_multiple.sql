--- insert_multiple tests inserting multiple session_credential_dynamic as a single statement
begin;
  select plan(6);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');
  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension        where organization_id      =  'o_____widget';
  select is(count(*), 0::bigint) from wh_credential_group_membership where credential_group_key != 'no credentials' and credential_group_key != 'Unknown';
  select is(count(*), 0::bigint) from wh_credential_group            where key                  != 'no credentials' and key                  != 'Unknown';

  --- multiple single credentials
  insert into session
    ( scope_id,      target_id,      host_set_id,    host_id,        user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 's___1wb-sths', 'h_____wb__01', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's1____walter');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s1____walter', 'vl______wvl1', null,           'application'),
    ('s1____walter', 'vl______wvl2', null,           'application'),
    ('s1____walter', 'vl______wvl3', null,           'application'),
    ('s1____walter', 'vl______wvl3', null,           'egress');

  select is(count(*), 4::bigint) from wh_credential_dimension        where organization_id      =  'o_____widget';
  select is(count(*), 4::bigint) from wh_credential_group_membership where credential_group_key != 'no credentials' and credential_group_key != 'Unknown';
  select is(count(*), 1::bigint) from wh_credential_group            where key                  != 'no credentials' and key                  != 'Unknown';

  select * from finish();
rollback;
