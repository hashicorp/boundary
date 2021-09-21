-- user_password_map_immutable_columns tests the following columns are
-- immutable:
--   private_id
--   library_id

begin;
  select plan(7);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  select is(count(*), 1::bigint) from credential_vault_library where public_id = 'vl______wvl1';
  select is(count(*), 0::bigint) from credential_vault_library_user_password_map where private_id = 'prv______up1';

  prepare insert_mapper as
    insert into credential_vault_library_user_password_map
      ( library_id,    private_id,     username_attribute, password_attribute )
    values
      ('vl______wvl1', 'prv______up1', 'v_username',       'v_password');
  select lives_ok('insert_mapper');

  select is(count(*), 1::bigint) from credential_vault_library_user_password_map where private_id = 'prv______up1';
  select is(count(*), 1::bigint) from credential_vault_library_map where private_id = 'prv______up1';

  -- Error code 23601 is a Boundary error code for an immutable column violation
  prepare update_library_id as
    update credential_vault_library_user_password_map
       set library_id = 'vl______wvl2'
     where private_id = 'prv______up1';
  select throws_ok('update_library_id', '23601');

  prepare update_private_id as
    update credential_vault_library_user_password_map
       set private_id = 'prv______up2'
     where library_id = 'vl______wvl1';
  select throws_ok('update_private_id', '23601');

  select * from finish();
rollback;
