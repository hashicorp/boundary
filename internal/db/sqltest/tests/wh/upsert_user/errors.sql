-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- errors tests that the wh_upsert_user function throws errors under certain conditions.
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- missing args
  select throws_ok($$select wh_upsert_user()$$);
  select throws_ok($$select wh_upsert_user('u_____walter')$$);

  -- non-existant user
  -- select throws_ok($$select wh_upsert_user('u_____retlaw', 'tok___walter')$$);

  -- non-existant token
  select throws_ok($$select wh_upsert_user('u_____walter', 'tok___retlaw')$$);

  select * from finish();
rollback;
