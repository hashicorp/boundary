-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- three_credentials_one_change tests that:
--  when a session with three credentials is created
--  three wh_credential_dimensions are created
--  then when one of the credential libraries is updated
--  and a new session is created
--  only one of the wh_credential_dimensions is updated
begin;
  select plan(12);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert session and session_credential_dynamic, should result in a three new credential dimensions
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
    ('s1____walter', 'vl______wvl3', null,           'brokered');

  select is(count(*), 3::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  prepare select_session_credential_group as
    select credential_library_id::text, credential_store_id::text, target_id::text, credential_purpose::text, credential_library_vault_path::text
      from wh_credential_dimension as wh_cd
      join wh_credential_group_membership as wh_cgm on
           wh_cd.key = wh_cgm.credential_key
      join wh_credential_group as wh_cg on
           wh_cg.key = wh_cgm.credential_group_key
      join wh_session_accumulating_fact as wh_saf on
           wh_saf.credential_group_key = wh_cg.key
     where wh_saf.session_id = 's1____walter';
  select results_eq(
    'select_session_credential_group',
    $$VALUES
      ('vl______wvl1', 'vs_______wvs', 't_________wb', 'brokered', '/secrets'),
      ('vl______wvl2', 'vs_______wvs', 't_________wb', 'brokered', '/secrets/ssh/admin'),
      ('vl______wvl3', 'vs_______wvs', 't_________wb', 'brokered', '/secrets/kv/one')$$
  );

  select isnt(wh_session_accumulating_fact.credential_group_key::text, 'no credentials')
    from wh_session_accumulating_fact
    where session_id = 's1____walter';

  insert into session_connection
    (session_id, public_id)
  values
    ('s1____walter', 'sc1____walter');

  select isnt(wh_session_connection_accumulating_fact.credential_group_key::text, 'no credentials')
    from wh_session_connection_accumulating_fact
    where session_id = 's1____walter';

  select is(wh_session_accumulating_fact.credential_group_key::text, wh_session_connection_accumulating_fact.credential_group_key::text, 'session fact and connection fact should have same credential group')
    from wh_session_connection_accumulating_fact
    join wh_session_accumulating_fact on wh_session_accumulating_fact.session_id = wh_session_connection_accumulating_fact.session_id
    where wh_session_connection_accumulating_fact.session_id = 's1____walter';

  update credential_vault_generic_library set vault_path = '/secrets/tcp/user' where public_id = 'vl______wvl2';

  insert into session
    ( project_id,     target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget', 't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's2____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s2____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id, credential_purpose)
  values
    ('s2____walter', 'vl______wvl1', null,          'brokered'),
    ('s2____walter', 'vl______wvl2', null,          'brokered'),
    ('s2____walter', 'vl______wvl3', null,          'brokered');

  select is(count(*), 4::bigint) from wh_credential_dimension where organization_id = 'o_____widget';
  select is(count(*), 3::bigint) from wh_credential_dimension where organization_id = 'o_____widget' and current_row_indicator = 'Current';

  select is(count(distinct(wh_session_accumulating_fact.credential_group_key)), 2::bigint)
    from wh_session_accumulating_fact
   where session_id = any(array['s1____walter', 's2____walter']);

  prepare select_updated_credential_dimension as
   select credential_library_vault_path::text
     from wh_credential_dimension
    where current_row_indicator = 'Current'
      and credential_library_id = 'vl______wvl2';
  select results_eq(
    'select_updated_credential_dimension',
    $$VALUES
      ('/secrets/tcp/user')$$
  );

  select is(count(*), 3::bigint) from wh_credential_dimension where organization_id = 'o_____widget' and current_row_indicator = 'Current';

  prepare select_second_session_credential_group as
    select credential_library_id::text, credential_store_id::text, target_id::text, credential_purpose::text, credential_library_vault_path::text
      from wh_credential_dimension as wh_cd
      join wh_credential_group_membership as wh_cgm on
           wh_cd.key = wh_cgm.credential_key
      join wh_credential_group as wh_cg on
           wh_cg.key = wh_cgm.credential_group_key
      join wh_session_accumulating_fact as wh_saf on
           wh_saf.credential_group_key = wh_cg.key
     where wh_saf.session_id = 's2____walter';
  select results_eq(
    'select_second_session_credential_group',
    $$VALUES
      ('vl______wvl1', 'vs_______wvs', 't_________wb', 'brokered','/secrets'),
      ('vl______wvl3', 'vs_______wvs', 't_________wb', 'brokered','/secrets/kv/one'),
      ('vl______wvl2', 'vs_______wvs', 't_________wb', 'brokered','/secrets/tcp/user')$$
  );

  select * from finish();
rollback;

