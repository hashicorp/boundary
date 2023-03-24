-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- credential_vault_store tests the credential_vault_store table

begin;

  select plan(3);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'vs_______cvs1';

  prepare soft_delete_credential_vault_store as
    update credential_vault_store
      set delete_time = clock_timestamp() -- Can't use now() or current_timestamp since constant within transaction
    where public_id = 'vs_______cvs1';

  -- First delete succeeds
  select lives_ok('soft_delete_credential_vault_store');
  -- Second delete fails because we can only set delete_time once
  select throws_ok('soft_delete_credential_vault_store', 'set_once_violation: credential_vault_store.delete_time', '23602');

  select * from finish();

rollback;
