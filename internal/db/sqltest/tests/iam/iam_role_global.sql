-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(14);
  select wtt_load('widgets', 'iam');

  --------------------------------------------------------------------------------
  -- 1) testing iam_role_global table constraints and insert_role_subtype
  --------------------------------------------------------------------------------

  -- 1a) insert a valid row -> should succeed and insert_role_subtype trigger
  prepare insert_valid_global_role as
    insert into iam_role_global 
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_1111111111', 'global', true, 'children');
  select lives_ok('insert_valid_global_role');

  -- verify it also created a row in base iam_role
  select is(count(*), 1::bigint) from iam_role where public_id = 'r_1111111111';

  -- 1b) try duplicate (public_id, grant_scope) => unique violation
  prepare insert_dup_public_id_grant_scope as
    insert into iam_role_global
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_1111111111', 'global', true, 'children');
  select throws_like(
    'insert_dup_public_id_grant_scope',
    'duplicate key value violates unique constraint "iam_role_pkey"',
    'unique(public_id) is enforced'
  );

  -- 1c) invalid grant_scope (not in iam_role_global_grant_scope_enm table)
  prepare insert_invalid_grant_scope as
    insert into iam_role_global
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_globeglobe', 'global', true, 'invalid_grant_scope');
  select throws_like(
    'insert_invalid_grant_scope',
    'insert or update on table "iam_role_global" violates foreign key constraint "iam_role_global_grant_scope_enm_fkey"',
    'invalid grant_scope must fail foreign key to iam_role_global_grant_scope_enm'
  );

  -- 1d) invalid scope_id -> must reference iam_scope_global(scope_id)
  prepare insert_bad_scope_id as
    insert into iam_role_global
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_globeglobe', 'does_not_exist', true, 'individual');
  select throws_like(
    'insert_bad_scope_id',
    'insert or update on table "iam_role" violates foreign key constraint "iam_scope_scope_id_fkey"',
    'scope_id must exist in iam_scope_global(scope_id)'
  );

  --------------------------------------------------------------------------------
  -- 2) testing insert_grant_scope_update_time trigger
  --------------------------------------------------------------------------------

  -- 2b) insert a new row (grant_this_role_scope, grant_scope) => should initialize
  prepare insert_with_grant_scope_update_time_set as
    insert into iam_role_global 
        (public_id, scope_id, grant_scope, grant_scope_update_time)
    values 
        ('r_2222222222', 'global', 'descendants', null);
  select lives_ok('insert_with_grant_scope_update_time_set');

  -- 2c) check if grant_scope_update_time is set
  select is(
    (select grant_scope_update_time is not null from iam_role_global where public_id = 'r_2222222222'),
    true,
    'grant_scope_update_time should be set with the default timestamp right after insert'
  );

  -- 2d) update grant_this_role_scope => trigger should update grant_scope_update_time timestamp
  prepare update_grant_this_role_scope as
    update iam_role_global
       set grant_this_role_scope = true
     where public_id = 'r_2222222222';
  select lives_ok('update_grant_this_role_scope');
  select is(
    (select grant_scope_update_time is not null from iam_role_global where public_id = 'r_2222222222'),
    true,
    'grant_scope_update_time should be set with the default timestamp right after insert'
  );

  --------------------------------------------------------------------------------
  -- 3) testing iam_role_global_individual_grant_scope table constraints
  --------------------------------------------------------------------------------
 
  --3a) insert invalid row: grant_scope != 'individual'
  prepare insert_invalid_individual_grant_scope as
    insert into iam_role_global_individual_grant_scope
        (role_id, scope_id, grant_scope)
    values
        ('r_3333333333', 'descendants', 'global');
  select throws_like(
    'insert_invalid_individual_grant_scope',
    'new row for relation "iam_role_global_individual_grant_scope" violates check constraint "only_individual_grant_scope_allowed"',
    'check(grant_scope = "individual") is enforced'
  );

  -- 3b) insert invalid row with a scope_id that is not global
  prepare insert_invalid_iam_role_global_individual_grant_scope as
    insert into iam_role_global_individual_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_1111111111', 'individual', 'o_1111111111');
  select throws_like(
        'insert_invalid_iam_role_global_individual_grant_scope',
        'insert or update on table "iam_role_global_individual_grant_scope" violates foreign key constraint "iam_scope_fkey"',
        'foreign key also enforces matching grant_scope=individual in iam_role_global'
  );

  -- 3c) insert invalid row where scope_id is 'global'
  prepare insert_iam_role_global_individual_scope_id as
    insert into iam_role_global_individual_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_1111111111', 'individual', 'global');
  select throws_like(
        'insert_iam_role_global_individual_scope_id',
        'new row for relation "iam_role_global_individual_grant_scope" violates check constraint "scope_id_is_not_global"',
        'check(scope_id != ''global'') is enforced'
  );

  -- 3d) insert valid iam_role_global_individual_grant_scope
  prepare insert_global_role_for_individual_scope as
    insert into iam_role_global 
        (public_id, scope_id, grant_scope)
    values
        ('r_3333333333', 'global', 'individual');
  select lives_ok('insert_global_role_for_individual_scope');

  prepare insert_valid_individual_org_scope as
    insert into iam_role_global_individual_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'o_____widget');
  select lives_ok('insert_valid_individual_org_scope');

  select * from finish();
rollback;
