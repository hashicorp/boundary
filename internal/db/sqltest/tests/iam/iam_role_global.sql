-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(44);
  select wtt_load('widgets', 'iam');

  --------------------------------------------------------------------------------
  -- 1) testing iam_role_global table constraints and insert_role_subtype
  --------------------------------------------------------------------------------

  -- 1a) insert a valid row -> should succeed and insert_role_subtype trigger
  -- r_1111111111 is a global role with grant_scope=descendants
  -- r_2222222222 is a global role with grant_scope=children
  -- r_3333333333 is a global role with grant_scope=individual
  prepare insert_valid_global_role as
    insert into iam_role_global 
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_1111111111', 'global', true, 'descendants'),
        ('r_2222222222', 'global', true, 'children'),
        ('r_3333333333', 'global', true, 'individual');
  select lives_ok('insert_valid_global_role');


  -- verify it also created a row in base iam_role
  select is(count(*), 1::bigint) from iam_role where public_id = 'r_1111111111';
  select is(count(*), 1::bigint) from iam_role where public_id = 'r_2222222222';
  select is(count(*), 1::bigint) from iam_role where public_id = 'r_3333333333';

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

  -- 2a) insert a new row (grant_this_role_scope, grant_scope) => should initialize
  prepare insert_with_grant_scope_update_time_set as
    insert into iam_role_global 
        (public_id, scope_id, grant_scope, grant_scope_update_time)
    values 
        ('r_4444444444', 'global', 'descendants', null);
  select lives_ok('insert_with_grant_scope_update_time_set');

  -- 2b) check if grant_scope_update_time is set
  select is(
    (select grant_scope_update_time is not null from iam_role_global where public_id = 'r_4444444444'),
    true,
    'grant_scope_update_time should be set with the default timestamp right after insert'
  );

  -- 2c) update grant_this_role_scope => trigger should update grant_scope_update_time timestamp
  prepare update_grant_this_role_scope as
    update iam_role_global
       set grant_this_role_scope = true
     where public_id = 'r_4444444444';
  select lives_ok('update_grant_this_role_scope');
  select is(
    (select grant_scope_update_time is not null from iam_role_global where public_id = 'r_4444444444'),
    true,
    'grant_scope_update_time should be set with the default timestamp right after insert'
  );

  --------------------------------------------------------------------------------
  -- 3) testing iam_role_global_individual_org_grant_scope table constraints
  --------------------------------------------------------------------------------
 
  -- 3a) insert invalid row: grant_scope = 'descendants'
  prepare insert_invalid_individual_org_grant_scope_descendants as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'descendants', 'p____bwidget');
  select throws_like(
    'insert_invalid_individual_org_grant_scope_descendants',
    'new row for relation "iam_role_global_individual_org_grant_scope" violates check constraint "only_individual_grant_scope_allowed"',
    'check(grant_scope = "individual") is enforced'
  );

  -- 3b) insert invalid row: grant_scope = 'children'
  prepare insert_invalid_individual_org_grant_scope_children as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'children', 'p____bwidget');
  select throws_like(
    'insert_invalid_individual_org_grant_scope_children',
    'new row for relation "iam_role_global_individual_org_grant_scope" violates check constraint "only_individual_grant_scope_allowed"',
    'check(grant_scope = "individual") is enforced'
  );

  -- 3c) insert invalid row with a scope_id that is not global
  prepare insert_invalid_iam_role_global_individual_org_grant_scope as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'o_1111111111');
  select throws_like(
        'insert_invalid_iam_role_global_individual_org_grant_scope',
        'insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_scope_org_fkey"',
        'foreign key also enforces matching grant_scope=individual in iam_role_global'
  );

  -- 3d) insert invalid row where scope_id is 'global'
  prepare insert_iam_role_global_individual_scope_id as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'global');
  select throws_like(
        'insert_iam_role_global_individual_scope_id',
        'insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_scope_org_fkey"',
        'check(scope_id != ''global'') is enforced'
  );

  -- 3e) insert invalid row where scope_id is a project
  prepare insert_invalid_project_into_individual_org_scope as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'p____bwidgetp____bwidget');
  select throws_like(
        'insert_iam_role_global_individual_scope_id',
        'insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_scope_org_fkey"',
        'foreign key also enforces matching grant_scope=individual in iam_role_global'
  );

  -- 3f) insert into iam_role_global_individual_org_grant_scope when role grant_scope is 'children'
  prepare insert_invalid_individual_org_scope as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_2222222222', 'individual', 'o_____widget');
  select throws_like(
        'insert_invalid_individual_org_scope',
        'insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_role_global_grant_scope_fkey"',
        'foreign key also enforces matching grant_scope=individual in iam_role_global'
  );

  -- 3g) insert into iam_role_global_individual_org_grant_scope when role grant_scope is descendants is not allowed
  -- r_1111111111 is a global role with grant_scope=descendants
  prepare iam_role_global_individual_org_grant_scope_role_descendants as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_1111111111', 'individual', 'o_____widget');
  select throws_like(
        'iam_role_global_individual_org_grant_scope_role_descendants',
        'insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_role_global_grant_scope_fkey"',
        'foreign key also enforces matching grant_scope=individual in iam_role_global'
  );


  -- 3h) insert into iam_role_global_individual_org_grant_scope when role grant_scope is children is not allowed
  -- r_2222222222 is a global role with grant_scope=children
  prepare iam_role_global_individual_org_grant_scope_role_children as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_2222222222', 'individual', 'o_____widget');
  select throws_like(
        'iam_role_global_individual_org_grant_scope_role_children',
        'insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_role_global_grant_scope_fkey"',
        'foreign key also enforces matching grant_scope=individual in iam_role_global'
  );


  --3i) insert entry with role_id that does not exist in iam_role_global
  prepare insert_invalid_role_id as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_1231231231', 'individual', 'p____bwidget');
  select throws_like(
    'insert_invalid_role_id',
    'insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_role_global_fkey"',
    'foreign key enforces that role exists in iam_role_global'
  );

  -- 3j) insert into iam_role_global_individual_org_grant_scope when role grant_scope is 'individual'
  -- r_3333333333 is a global role with grant_scope=individual
  prepare insert_valid_individual_org_scope as
    insert into iam_role_global_individual_org_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'o_____widget');
  select lives_ok('insert_valid_individual_org_scope');



  --------------------------------------------------------------------------------
  -- 4) testing iam_role_global_individual_project_grant_scope table constraints
  --------------------------------------------------------------------------------
 
  -- 4a) insert invalid row: grant_scope = 'descendants'
  prepare insert_invalid_individual_project_grant_scope_descendants as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'descendants', 'p____bwidget');
  select throws_like(
    'insert_invalid_individual_project_grant_scope_descendants',
    'new row for relation "iam_role_global_individual_project_grant_scope" violates check constraint "only_individual_or_children_grant_scope_allowed"',
    'check(grant_scope in ["children", "individual"]) is enforced'
  );

  -- 4b) insert invalid row: grant_scope = 'children'
  prepare insert_invalid_individual_project_grant_scope_children as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'children', 'p____bwidget');
  select throws_like(
    'insert_invalid_individual_project_grant_scope_children',
    'insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_role_global_grant_scope_fkey"',
    'foreign key to grant_scope in iam_role_global is enforced'
  );

  -- 4c) insert invalid row with a scope_id project does not exist
  prepare insert_invalid_iam_role_global_individual_project_grant_scope as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'p_1111111111');
  select throws_like(
        'insert_invalid_iam_role_global_individual_project_grant_scope',
        'insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_scope_project_fkey"',
        'foreign key also enforces matching grant_scope=individual in iam_role_global'
  );

  -- 4d) insert invalid row where scope_id is 'global'
  prepare insert_invalid_project_grant_scope_global as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'global');
  select throws_like(
        'insert_invalid_project_grant_scope_global',
        'insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_scope_project_fkey"',
        'check(scope_id != ''global'') is enforced'
  );

  -- 4e) insert invalid row where scope_id is an org
  prepare insert_invalid_org_into_individual_proj_scope as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'o_____widget');
  select throws_like(
        'insert_invalid_org_into_individual_proj_scope',
        'insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_scope_project_fkey"',
        'foreign key enforces that scope_id is a project scope'
  );

  -- 4f) insert into iam_role_global_individual_project_grant_scope when role grant_scope is descendants is not allowed
  -- r_1111111111 is a global role with grant_scope=descendants
  prepare iam_role_global_individual_project_grant_scope_role_descendants as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_1111111111', 'individual', 'p_____widget');
  select throws_like(
        'iam_role_global_individual_project_grant_scope_role_descendants',
        'insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_scope_project_fkey"',
        'foreign key enforces that scope_id is a project scope'
  );

  -- 4g) insert entry with role_id that does not exist in iam_role_global
  prepare insert_invalid_role_id_proj_grants_scope as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_1231231231', 'individual', 'p____bwidget');
  select throws_like(
    'insert_invalid_role_id_proj_grants_scope',
    'insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_role_global_fkey"',
    'foreign key enforces that role exists in iam_role_global'
  );


  -- 4h) insert into iam_role_global_individual_project_grant_scope when role grant_scope is 'children' is valid
  -- r_2222222222 is a global role with grant_scope=children
  prepare insert_valid_individual_project_scope_children_grants as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_2222222222', 'children', 'p____bwidget');
  select lives_ok('insert_valid_individual_project_scope_children_grants');

  -- 4i) insert into iam_role_global_individual_project_grant_scope when role grant_scope is 'individual'
  -- r_3333333333 is a global role with grant_scope=individual
  prepare insert_valid_individual_project_scope as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_3333333333', 'individual', 'p____bwidget');
  select lives_ok('insert_valid_individual_project_scope');



  -- 4j) update to iam_role_global.grant_scope from children to individual cascades to iam_role_global_individual_project_grant_scope.grant_scope
  -- r_5555555555 is a global role with grant_scope=children
  prepare insert_valid_global_role_children_grants as
    insert into iam_role_global 
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_5555555555', 'global', true, 'children');
  select lives_ok('insert_valid_global_role_children_grants');

  -- create a row in iam_role_global_individual_project_grant_scope with grant_scope=children
  prepare insert_valid_project_scope_to_children_grants as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_5555555555', 'children', 'p____bwidget');
  select lives_ok('insert_valid_project_scope_to_children_grants');

  -- take away children grants by updating to iam_role_global to individual
  prepare update_grant_scope_to_individual as
    update iam_role_global
        set grant_scope = 'individual'
      where public_id = 'r_5555555555';
    select lives_ok('update_grant_scope_to_individual');
  
  -- check that the update cascaded to iam_role_global_individual_project_grant_scope
  -- and that the grant_scope is now individual
  select is(count(*), 1::bigint) from iam_role_global_individual_project_grant_scope where role_id = 'r_5555555555' and grant_scope = 'individual';


  -- 4k) update to iam_role_global.grant_scope from children to individual cascades to iam_role_global_individual_project_grant_scope.grant_scope
  -- r_6666666666 is a global role with grant_scope=individual and is granted individual org and project 
  prepare insert_valid_global_role_individual_grants as
    insert into iam_role_global 
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_6666666666', 'global', true, 'individual');
  select lives_ok('insert_valid_global_role_individual_grants');

  -- create a row in iam_role_global_individual_project_grant_scope with grant_scope=individual
  prepare insert_valid_project_scope_to_individual_grants as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_6666666666', 'individual', 'p____bwidget');
  select lives_ok('insert_valid_project_scope_to_individual_grants');

  -- take away children grants by updating to iam_role_global to children
  prepare update_grant_scope_to_children as
    update iam_role_global
        set grant_scope = 'children'
      where public_id = 'r_6666666666';
    select lives_ok('update_grant_scope_to_children');
  
  -- verify that iam_role_global.grant_scope is updated to children
  select is(count(*), 1::bigint) from iam_role_global where public_id = 'r_6666666666' and grant_scope = 'children';
  -- check that the update cascaded to iam_role_global_individual_project_grant_scope and iam_role_global_individual_org_grant_scope
  -- and that the grant_scope is now children
  select is(count(*), 1::bigint) from iam_role_global_individual_project_grant_scope where role_id = 'r_6666666666' and scope_id = 'p____bwidget' and grant_scope = 'children';


  -- 4l) update to iam_role_global.grant_scope from children to individual sets
  -- individually granted project scope in iam_role_global_individual_project_grant_scope grant_scope to children
  prepare insert_r8_valid_global_scope_to_individual_grants as
    insert into iam_role_global 
        (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
        ('r_8888888888', 'global', true, 'children');
  select lives_ok('insert_r8_valid_global_scope_to_individual_grants');

  -- create a row in iam_role_global_individual_project_grant_scope with grant_scope=children
  prepare insert_r8_valid_project_scope_to_children_grants as
    insert into iam_role_global_individual_project_grant_scope
        (role_id, grant_scope, scope_id)
    values
        ('r_8888888888', 'children', 'p____bwidget');
  select lives_ok('insert_r8_valid_project_scope_to_children_grants');

  -- take away children grants by updating to iam_role_global to individual
  prepare update_r8_grant_scope_to_individual as
    update iam_role_global
        set grant_scope = 'individual'
      where public_id = 'r_8888888888';
    select lives_ok('update_r8_grant_scope_to_individual');
  
  -- verify that iam_role_global.grant_scope is updated to individual
  select is(count(*), 1::bigint) from iam_role_global where public_id = 'r_8888888888' and grant_scope = 'individual';
  -- check that the update deletes all individual grant scopes in iam_role_global_individual_org_grant_scope and iam_role_global_individual_project_grant_scope
  select is(count(*), 1::bigint) from iam_role_global_individual_project_grant_scope where role_id = 'r_8888888888' and grant_scope = 'individual' and scope_id = 'p____bwidget';

  select * from finish();
rollback;
