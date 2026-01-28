-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- credential_vault_library tests:
--   the following triggers
--    insert_credential_library_subtype
--    delete_credential_library_subtype

begin;
  select plan(10);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select is(count(*), 1::bigint) from credential_vault_generic_library where public_id = 'vl______wvl1' and credential_type = 'unspecified';
  select is(count(*), 1::bigint) from credential_library where public_id = 'vl______wvl1' and credential_type = 'unspecified';

  select is(count(*), 1::bigint) from credential_vault_generic_library where public_id = 'vl______wvl3' and credential_type = 'username_password';
  select is(count(*), 1::bigint) from credential_library where public_id = 'vl______wvl3' and credential_type = 'username_password';

  -- validate the insert triggers
  prepare insert_vault_library as
    insert into credential_vault_generic_library
      (store_id,       public_id,      vault_path,           http_method, credential_type)
    values
      ('vs_______wvs', 'vl_______tt1', '/secrets/kv',        'GET',       'username_password');
  select lives_ok('insert_vault_library');

  select is(count(*), 1::bigint) from credential_vault_generic_library where public_id = 'vl_______tt1' and credential_type = 'username_password';
  select is(count(*), 1::bigint) from credential_library where public_id = 'vl_______tt1' and credential_type = 'username_password';

  -- validate the delete triggers
  prepare delete_vault_library as
    delete
      from credential_vault_generic_library
     where public_id = 'vl_______tt1';
  select lives_ok('delete_vault_library');

  select is(count(*), 0::bigint) from credential_vault_generic_library where public_id = 'vl_______tt1';
  select is(count(*), 0::bigint) from credential_library where public_id = 'vl_______tt1';

  select * from finish();
rollback;
