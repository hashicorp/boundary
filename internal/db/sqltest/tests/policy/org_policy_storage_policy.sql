-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(6);

  -- create a storage policy
  prepare insert_policy as
    insert into policy_storage_policy
      (public_id,       scope_id,       retain_for_days, delete_after_days)
    values
      ('pst_test1234',  'o__foodtruck', 1,               0);
  select lives_ok('insert_policy');

  select is(count(*), 1::bigint) from policy_storage_policy where public_id = 'pst_test1234';
  select is(count(*), 1::bigint) from policy where public_id = 'pst_test1234';

  -- deleting org should also delete the storage policy creating in that org
  prepare delete_org as
    delete from iam_scope
     where type = 'org'
       and public_id = 'o__foodtruck';

  select lives_ok('delete_org');

  select is(count(*), 0::bigint) from policy_storage_policy where public_id = 'pst_test1234';
  select is(count(*), 0::bigint) from policy where public_id = 'pst_test1234';

rollback;
