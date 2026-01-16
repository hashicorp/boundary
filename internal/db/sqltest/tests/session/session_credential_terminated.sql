-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- session_credential tests:
--   the following triggers
--    delete_session_credentials

begin;
  select plan(4);
  select wtt_load('widgets', 'iam', 'kms', 'auth');

  -- validate the setup data
  select is(count(*), 1::bigint) from session where public_id = 's1_____clare';

  insert into session_credential
    ( session_id   , credential                 , key_id)
  values
    ('s1_____clare', 'clare credential data 1' , 'kdkv___widget'),
    ('s1_____clare', 'clare credential data 2' , 'kdkv___widget'),
    ('s1_____clare', 'clare credential data 3' , 'kdkv___widget');

  select is(count(*), 3::bigint) from session_credential where session_id = 's1_____clare';

  -- validate the delete triggers
  prepare delete_session_credentials as
    insert into session_state
      (session_id     , state)
    values
      ('s1_____clare' , 'terminated');
  select lives_ok('delete_session_credentials');

  select is(count(*), 0::bigint) from session_credential where session_id = 's1_____clare';

  select * from finish();
rollback;
