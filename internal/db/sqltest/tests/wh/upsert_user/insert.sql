-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

-- insert tests that the wh_upsert_user function will do an insert when
-- no existing source wh_user_dimension exists.
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_user_dimension where user_id = 'u_____walter';

  select lives_ok($$select wh_upsert_user('u_____walter', 'tok___walter')$$);

  -- upsert should insert a user_dimension
  select is(count(*), 1::bigint) from wh_user_dimension where user_id = 'u_____walter';

  select * from finish();
rollback;
