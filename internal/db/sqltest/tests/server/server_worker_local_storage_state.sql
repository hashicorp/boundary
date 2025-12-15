-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(1);

  -- Insert valid local_storage_state values
  insert into server_worker
    (public_id,        scope_id,   type,   local_storage_state)
  values
    ('w_1234567891',   'global',   'pki',  'available');

  insert into server_worker
    (public_id,        scope_id,   type,   local_storage_state)
  values
    ('w_1234567892',   'global',   'pki',  'low storage');

  insert into server_worker
    (public_id,        scope_id,   type,   local_storage_state)
  values
    ('w_1234567893',   'global',   'pki',  'critically low storage');

  insert into server_worker
    (public_id,        scope_id,   type,   local_storage_state)
  values
    ('w_1234567894',   'global',   'pki',  'out of storage');

  insert into server_worker
    (public_id,        scope_id,   type,   local_storage_state)
  values
    ('w_1234567895',   'global',   'pki',  'not configured');

  insert into server_worker
    (public_id,        scope_id,   type,   local_storage_state)
  values
    ('w_1234567896',   'global',   'pki',  'unknown'); 

  -- Try to insert invalid local_storage_state value to test constraint
  prepare invalid_local_storage_state_value as
    insert into server_worker
      (public_id,       scope_id,   type,   local_storage_state)
    values
      ('w_1234567897',  'global',   'pki',  'invalid state');
  select throws_ok(
    'invalid_local_storage_state_value',
    '23503',
    'insert or update on table "server_worker" violates foreign key constraint "server_worker_local_storage_state_state_enm_fkey"', 
    'inserting a row with invalid local_storage_state value'
  );  

  select * from finish();
rollback;
