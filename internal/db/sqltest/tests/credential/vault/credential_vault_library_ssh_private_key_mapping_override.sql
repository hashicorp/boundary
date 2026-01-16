-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

--  credential_vault_library_ssh_private_key_mapping_override tests:
--   the following triggers
--    insert_credential_vault_generic_library_mapping_override_subtyp
--    delete_credential_vault_generic_library_mapping_override_subtyp
--   and the following view
--    credential_vault_generic_library_list_lookup

begin;
  select plan(11);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select is(count(*), 4::bigint)
    from credential_vault_generic_library_ssh_private_key_mapping_ovrd
   where library_id in ('vl______wvl9', 'vl______wvl10', 'vl______wvl11', 'vl______wvl12');

  select is(count(*), 4::bigint)
    from credential_vault_generic_library_mapping_override
   where library_id in ('vl______wvl9', 'vl______wvl10', 'vl______wvl11', 'vl______wvl12');

  prepare select_libraries as
   select public_id::text, credential_type::text, username_attribute::text, private_key_attribute::text, private_key_passphrase_attribute::text
     from credential_vault_generic_library_list_lookup
    where public_id in ('vl______wvl2', 'vl______wvl8', 'vl______wvl9', 'vl______wvl10', 'vl______wvl11', 'vl______wvl12')
 order by public_id;

  select results_eq(
      'select_libraries',
      $$VALUES
      ('vl______wvl10', 'ssh_private_key', 'my_username', null, null),
      ('vl______wvl11', 'ssh_private_key', null,          'my_private_key', null),
      ('vl______wvl12', 'ssh_private_key', 'my_username', 'my_private_key', 'my_passphrase'),
      ('vl______wvl2',  'unspecified',     null,          null,             null),
      ('vl______wvl8',  'ssh_private_key', null,          null,             null),
      ('vl______wvl9',  'ssh_private_key', null,          null,             null)$$
  );

  -- validate the insert triggers
  select is(count(*), 0::bigint) from credential_vault_generic_library_ssh_private_key_mapping_ovrd where library_id = 'vl______wvl8';
  select is(count(*), 0::bigint) from credential_vault_generic_library_mapping_override             where library_id = 'vl______wvl8';

  prepare insert_cvl_ssh_private_key_mapping_override as
    insert into credential_vault_generic_library_ssh_private_key_mapping_ovrd
      (library_id,     username_attribute, private_key_attribute)
    values
      ('vl______wvl8', 'my_username',      'my_private_key');
  select lives_ok('insert_cvl_ssh_private_key_mapping_override');

  select is(count(*), 1::bigint) from credential_vault_generic_library_ssh_private_key_mapping_ovrd where library_id = 'vl______wvl8';
  select is(count(*), 1::bigint) from credential_vault_generic_library_mapping_override             where library_id = 'vl______wvl8';

  -- validate the delete triggers
  prepare delete_cvl_ssh_private_key_mapping_override as
    delete
      from credential_vault_generic_library_ssh_private_key_mapping_ovrd
     where library_id = 'vl______wvl8';
  select lives_ok('delete_cvl_ssh_private_key_mapping_override');

  select is(count(*), 0::bigint) from credential_vault_generic_library_ssh_private_key_mapping_ovrd where library_id = 'vl______wvl8';
  select is(count(*), 0::bigint) from credential_vault_generic_library_mapping_override             where library_id = 'vl______wvl8';

  select * from finish();
rollback;
