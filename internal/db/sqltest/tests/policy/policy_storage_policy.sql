-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(12);

  -- helper statements for resetting test env 
  prepare delete_policy_storage_policy_resource as
    delete from policy_storage_policy where public_id = 'pst__bcolors';

  -- test constraints

  -- retain_for_days and delete_after_days both cannot be set to 0
  prepare insert_policy_delete_after_days_and_retain_for_days_zero as
    insert into policy_storage_policy
      (public_id,       scope_id,      retain_for_days, delete_after_days)
    values
      ('pst__bcolors', 'global',       0,               0);
  select throws_ok('insert_policy_delete_after_days_and_retain_for_days_zero', 'P0001', null, 'delete_after_days and retain_for_days both cannot be zero');
  select lives_ok('delete_policy_storage_policy_resource', 'policy_storage_policy cleanup');

  prepare insert_policy_delete_after_days_negative as
    insert into  policy_storage_policy
      (public_id,       scope_id,      retain_for_days, delete_after_days)
    values
      ('pst__bcolors', 'global',       10,              -1);
  select throws_ok('insert_policy_delete_after_days_negative', 23514, null, 'delete_after_days cannot be negative');
  select lives_ok('delete_policy_storage_policy_resource', 'policy_storage_policy cleanup');

  prepare insert_policy_delete_after_days_while_inf_retain as
    insert into  policy_storage_policy
      (public_id,       scope_id,      retain_for_days, delete_after_days)
    values
      ('pst__bcolors', 'global',       -1,              10);
  select throws_ok('insert_policy_delete_after_days_while_inf_retain', 'P0001', null, 'delete_after_days must be 0 while retain_for_days is inf');
  select lives_ok('delete_policy_storage_policy_resource', 'policy_storage_policy cleanup');

  prepare insert_policy_delete_after_less_than_retain as
    insert into  policy_storage_policy
      (public_id,       scope_id,      retain_for_days, delete_after_days)
    values
      ('pst__bcolors', 'global',       6,               5);
  select throws_ok('insert_policy_delete_after_less_than_retain', 23514, null, 'delete_after must be greater than or equal to retain_for');
  select lives_ok('delete_policy_storage_policy_resource', 'policy_storage_policy cleanup');

  prepare retain_for_days_max as
    insert into  policy_storage_policy
    (public_id,       scope_id,      retain_for_days, delete_after_days)
    values
    ('pst__bcolors', 'global',       40000,           0);
  select throws_ok('retain_for_days_max', 23514);
  select lives_ok('delete_policy_storage_policy_resource', 'policy_storage_policy cleanup');

  prepare delete_after_days_max as
    insert into  policy_storage_policy
    (public_id,       scope_id,      retain_for_days, delete_after_days)
    values
    ('pst__bcolors', 'global',       0,               40000);
  select throws_ok('delete_after_days_max', 23514);
  select lives_ok('delete_policy_storage_policy_resource', 'policy_storage_policy cleanup');

rollback;
