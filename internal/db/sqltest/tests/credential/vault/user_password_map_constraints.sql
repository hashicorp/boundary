-- user_password_map_constraints tests the following constraints on
-- the credential_vault_library_user_password_map table:
--   username cannot be null
--   username cannot be an empty string
--   password cannot be null
--   password cannot be an empty string

begin;
  select plan(6);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  select is(count(*), 1::bigint) from credential_vault_library where public_id = 'vl______wvl1';
  select is(count(*), 0::bigint) from credential_vault_library_user_password_map where private_id = 'prv______up1';

  -- Error code 23502 is a not_null_violation
  -- Error code 23514 is a check_violation
  --
  -- https://www.postgresql.org/docs/current/errcodes-appendix.html

  prepare null_username_attribute as
    insert into credential_vault_library_user_password_map
      ( library_id,    private_id,     password_attribute, username_attribute)
    values
      ('vl______wvl1', 'prv______up1', 'v_password',       null);
  select throws_ok('null_username_attribute', '23502');

  prepare empty_username_attribute as
    insert into credential_vault_library_user_password_map
      ( library_id,    private_id,     password_attribute, username_attribute)
    values
      ('vl______wvl1', 'prv______up1', 'v_password',       '   ');
  select throws_ok('empty_username_attribute', '23514');

  prepare null_password_attribute as
    insert into credential_vault_library_user_password_map
      ( library_id,    private_id,     username_attribute, password_attribute)
    values
      ('vl______wvl1', 'prv______up1', 'v_username',       null);
  select throws_ok('null_password_attribute', '23502');

  prepare empty_password_attribute as
    insert into credential_vault_library_user_password_map
      ( library_id,    private_id,     username_attribute, password_attribute)
    values
      ('vl______wvl1', 'prv______up1', 'v_username',       '   ');
  select throws_ok('empty_password_attribute', '23514');

  select * from finish();
rollback;
