-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(10);

  -- Verify the trigger functions exist and are declared properly
  select has_function('insert_deleted_id');
  select volatility_is('insert_deleted_id', 'volatile');
  select isnt_strict('insert_deleted_id');
  select has_trigger('auth_token', 'insert_deleted_id');

  -- To test the trigger that moves deleted rows into their appropriate tables, we'll use auth_token
  -- Ensure session state table is populated, and session_deleted and auth_token_deleted tables are empty
  select is(count(*), 1::bigint) from session_state where session_id = 's1_____clare';
  select is(count(*), 0::bigint) from session_deleted;
  select is(count(*), 0::bigint) from auth_token_deleted;

  -- Check that we have a session for a particular auth token
  select is(count(*), 2::bigint) from session where auth_token_id = 'tok____clare';

  -- Delete auth tokens, expect no errors, check that the auth_token table is now populated
  delete from auth_token where public_id = 'tok____clare';
  select is(count(*), 0::bigint) from auth_token where public_id = 'tok____clare';
  select is(count(*), 1::bigint) from auth_token_deleted;

  select * from finish();

rollback;
