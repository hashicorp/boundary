-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

--  credential_vault_library_username_password_mapping_override tests:
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
    from credential_vault_generic_library_username_password_mapping_ovrd
   where library_id in ('vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7');

  select is(count(*), 4::bigint)
    from credential_vault_generic_library_mapping_override
   where library_id in ('vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7');

  prepare select_libraries as
   select public_id::text, credential_type::text, username_attribute::text, password_attribute::text
     from credential_vault_generic_library_list_lookup
    where public_id in ('vl______wvl2', 'vl______wvl3', 'vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7')
 order by public_id;

  select results_eq(
      'select_libraries',
      $$VALUES
      ('vl______wvl2', 'unspecified',   null,          null),
      ('vl______wvl3', 'username_password', null,          null),
      ('vl______wvl4', 'username_password', null,          null),
      ('vl______wvl5', 'username_password', 'my_username', null),
      ('vl______wvl6', 'username_password', null,          'my_password'),
      ('vl______wvl7', 'username_password', 'my_username', 'my_password')$$
  );

  -- validate the insert triggers
  select is(count(*), 0::bigint) from credential_vault_generic_library_username_password_mapping_ovrd where library_id = 'vl______wvl3';
  select is(count(*), 0::bigint) from credential_vault_generic_library_mapping_override               where library_id = 'vl______wvl3';

  prepare insert_cvl_username_password_mapping_override as
    insert into credential_vault_generic_library_username_password_mapping_ovrd
      (library_id,     username_attribute, password_attribute)
    values
      ('vl______wvl3', 'my_username',      'my_password');
  select lives_ok('insert_cvl_username_password_mapping_override');

  select is(count(*), 1::bigint) from credential_vault_generic_library_username_password_mapping_ovrd where library_id = 'vl______wvl3';
  select is(count(*), 1::bigint) from credential_vault_generic_library_mapping_override               where library_id = 'vl______wvl3';

  -- validate the delete triggers
  prepare delete_cvl_username_password_mapping_override as
    delete
      from credential_vault_generic_library_username_password_mapping_ovrd
     where library_id = 'vl______wvl3';
  select lives_ok('delete_cvl_username_password_mapping_override');

  select is(count(*), 0::bigint) from credential_vault_generic_library_username_password_mapping_ovrd where library_id = 'vl______wvl3';
  select is(count(*), 0::bigint) from credential_vault_generic_library_mapping_override               where library_id = 'vl______wvl3';

  select * from finish();
rollback;
