-- credential_vault_library_map tests:
--   the following columns are immutable:
--     private_id
--     library_id
-- and
--   a library can only have one mapper

begin;
  select plan(7);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  select is(count(*), 1::bigint) from credential_vault_library where public_id = 'vl______wvl1';
  select is(count(*), 0::bigint) from credential_vault_library_map where private_id = 'prv______up1';

  prepare insert_mapper as
    insert into credential_vault_library_map
      ( library_id,    private_id )
    values
      ('vl______wvl1', 'prv______up1');
  select lives_ok('insert_mapper');

  select is(count(*), 1::bigint) from credential_vault_library_map where private_id = 'prv______up1';

  -- Error code 23505 is a unique_violation
  --
  -- https://www.postgresql.org/docs/current/errcodes-appendix.html

  -- One mapper per library
  prepare insert_second_mapper as
    insert into credential_vault_library_map
      ( library_id,    private_id )
    values
      ('vl______wvl1', 'prv______up2');
  select throws_ok('insert_second_mapper', '23505');

  -- Error code 23601 is a Boundary error code for an immutable column violation
  prepare update_library_id as
    update credential_vault_library_map
       set library_id = 'vl______wvl2'
     where private_id = 'prv______up1';
  select throws_ok('update_library_id', '23601');

  prepare update_private_id as
    update credential_vault_library_map
       set private_id = 'prv______up2'
     where library_id = 'vl______wvl1';
  select throws_ok('update_private_id', '23601');

  select * from finish();
rollback;
