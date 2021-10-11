--  credential_vault_library_user_password_mapping_override tests:
--   the following triggers
--    insert_credential_vault_library_mapping_override_subtype
--    delete_credential_vault_library_mapping_override_subtype

begin;
  select plan(10);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select is(count(*), 4::bigint)
    from credential_vault_library_user_password_mapping_override
   where library_id in ('vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7');

  select is(count(*), 4::bigint)
    from credential_vault_library_mapping_override
   where library_id in ('vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7');

  -- validate the insert triggers
  select is(count(*), 0::bigint) from credential_vault_library_user_password_mapping_override where library_id = 'vl______wvl3';
  select is(count(*), 0::bigint) from credential_vault_library_mapping_override               where library_id = 'vl______wvl3';

  prepare insert_credential_vault_library_user_password_mapping_override as
    insert into credential_vault_library_user_password_mapping_override
      (library_id,     username_attribute, password_attribute)
    values
      ('vl______wvl3', 'my_username',      'my_password');
  select lives_ok('insert_credential_vault_library_user_password_mapping_override');

  select is(count(*), 1::bigint) from credential_vault_library_user_password_mapping_override where library_id = 'vl______wvl3';
  select is(count(*), 1::bigint) from credential_vault_library_mapping_override               where library_id = 'vl______wvl3';

  -- validate the delete triggers
  prepare delete_credential_vault_library_user_password_mapping_override as
    delete
      from credential_vault_library_user_password_mapping_override
     where library_id = 'vl______wvl3';
  select lives_ok('delete_credential_vault_library_user_password_mapping_override');

  select is(count(*), 0::bigint) from credential_vault_library_user_password_mapping_override where library_id = 'vl______wvl3';
  select is(count(*), 0::bigint) from credential_vault_library_mapping_override               where library_id = 'vl______wvl3';

  select * from finish();
rollback;
