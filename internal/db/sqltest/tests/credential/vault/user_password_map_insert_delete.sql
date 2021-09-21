-- user_password_map_insert_delete tests that:
--   when a row is inserted into credential_vault_library_user_password_map a row
--   is inserted into credential_vault_library_map
-- and
--   when a row is deleted from credential_vault_library_user_password_map a row
--   is deleted from credential_vault_library_map
-- and
--   a library can only have one mapper

begin;
  select plan(10);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  select is(count(*), 1::bigint) from credential_vault_library where public_id = 'vl______wvl1';
  select is(count(*), 0::bigint) from credential_vault_library_user_password_map where private_id = 'prv______up1';
  select is(count(*), 0::bigint) from credential_vault_library_map where private_id = 'prv______up1';

  prepare insert_mapper as
    insert into credential_vault_library_user_password_map
      ( library_id,    private_id,     username_attribute, password_attribute )
    values
      ('vl______wvl1', 'prv______up1', 'v_username',       'v_password');
  select lives_ok('insert_mapper');

  select is(count(*), 1::bigint) from credential_vault_library_user_password_map where private_id = 'prv______up1';
  select is(count(*), 1::bigint) from credential_vault_library_map where private_id = 'prv______up1';

  -- Error code 23505 is a unique_violation
  --
  -- https://www.postgresql.org/docs/current/errcodes-appendix.html

  -- One mapper per library
  prepare insert_second_mapper as
    insert into credential_vault_library_user_password_map
      ( library_id,    private_id,     username_attribute, password_attribute )
    values
      ('vl______wvl1', 'prv______up2', 'v_username',       'v_password');
  select throws_ok('insert_second_mapper', '23505');

  prepare delete_mapper as
    delete from credential_vault_library_user_password_map where library_id = 'vl______wvl1';
  select lives_ok('delete_mapper');

  select is(count(*), 0::bigint) from credential_vault_library_user_password_map where private_id = 'prv______up1';
  select is(count(*), 0::bigint) from credential_vault_library_map where private_id = 'prv______up1';

  select * from finish();
rollback;
