-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(22);
  select wtt_load('widgets', 'iam');

  ------------------------------------------------------------------------------
  -- 1) testing iam_role_org table constraints and insert_role_subtype
  ------------------------------------------------------------------------------

  -- 1a) insert a valid row -> should succeed and fire insert_role_subtype trigger
  prepare insert_valid_org_role as
    insert into iam_role_org
      (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
      ('r_org_1111111111', 
       'o_____widget',      
       true,
       'children'           
      );

  select lives_ok('insert_valid_org_role');

  -- verify it also created a row in base iam_role
  select is(
    (select count(*) from iam_role where public_id = 'r_org_1111111111'),
    1::bigint,
    'insert_role_subtype trigger inserted a row into iam_role'
  );

  -- 1b) try duplicate (public_id, grant_scope) => unique violation
  prepare insert_dup_public_id_grant_scope as
    insert into iam_role_org
      (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
      ('r_org_1111111111', 'o_____widget', true, 'children');
  select throws_like(
    'insert_dup_public_id_grant_scope',
    'duplicate key value violates unique constraint "iam_role_pkey"',
    'unique(public_id, grant_scope) is enforced on iam_role_org'
  );

  -- 1c) invalid grant_scope (not in iam_role_org_grant_scope_enm)
  prepare insert_invalid_grant_scope as
    insert into iam_role_org
      (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
      ('r_org_bad_grscope', 'o_____widget', true, 'invalid_scope');
  select throws_like(
    'insert_invalid_grant_scope',
    'insert or update on table "iam_role_org" violates foreign key constraint "iam_role_org_grant_scope_enm_fkey"',
    'invalid grant_scope must fail foreign key to iam_role_org_grant_scope_enm'
  );

  -- 1d) invalid scope_id -> must reference iam_scope_org(scope_id)
  prepare insert_bad_scope_id as
    insert into iam_role_org
      (public_id, scope_id, grant_this_role_scope, grant_scope)
    values
      ('r_org_bad_scope', 'x_no_such_scope', true, 'children');
  select throws_like(
    'insert_bad_scope_id',
    'insert or update on table "iam_role" violates foreign key constraint "iam_scope_scope_id_fkey"',
    'scope_id must exist in iam_scope_org(scope_id)'
  );

  -- 1e) attempt referencing a project scope from iam_scope_project, expecting an error
  prepare insert_wrong_scope_type as
    insert into iam_role_org
      (public_id, scope_id, grant_scope, grant_this_role_scope)
    values
      ('r_org_wrong_scope', 'p____bwidget', 'children', true);
  select throws_like(
    'insert_wrong_scope_type',
    'insert or update on table "iam_role_org" violates foreign key constraint "iam_scope_org_fkey"',
    'must reference an org scope, not a project scope'
  );

  ------------------------------------------------------------------------------
  -- 2) testing grant_scope_update_time trigger
  ------------------------------------------------------------------------------

  -- 2a) insert a row -> expect it to set grant_scope_update_time (if triggered on insert)
  prepare insert_with_grant_scope_update_time as
    insert into iam_role_org
      (public_id, scope_id, grant_scope, grant_scope_update_time)
    values
      ('r_org_2222222222', 'o_____widget', 'individual', null);
  select lives_ok('insert_with_grant_scope_update_time');

  select is(
    (select grant_scope_update_time is not null
       from iam_role_org
      where public_id = 'r_org_2222222222'),
    true,
    'grant_scope_update_time should be set right after insert if the trigger sets it'
  );

  -- 2b) update grant_this_role_scope => trigger should update grant_this_role_scope_update_time
  
  -- update grant_this_role_scope_update_time to default
  prepare reset_grant_this_role_scope_update_time as
    update iam_role_org
       set grant_this_role_scope_update_time = '1970-01-01 00:00:00'
     where public_id = 'r_org_2222222222';
  select lives_ok('reset_grant_this_role_scope_update_time');

  prepare update_grant_this_role_scope as
    update iam_role_org
       set grant_this_role_scope = true
     where public_id = 'r_org_2222222222';
  select lives_ok('update_grant_this_role_scope');

  select is(
    (select grant_this_role_scope_update_time is not null
       from iam_role_org
      where public_id = 'r_org_2222222222'),
    true,
    'grant_this_role_scope_update_time should be updated after changing grant_this_role_scope'
  );

  select is(
    (select grant_this_role_scope_update_time = now()
       from iam_role_org
      where public_id = 'r_org_2222222222'),
    true,
    'grant_this_role_scope_update_time should be updated after changing grant_this_role_scope'
  );


  -- 2c) update grant_scope => trigger should update grant_this_role_scope_update_time
  
  prepare reset_grant_scope_update_time as
    update iam_role_org
       set grant_scope_update_time = '1970-01-01 00:00:00'
     where public_id = 'r_org_2222222222';
  select lives_ok('reset_grant_scope_update_time');

  prepare update_grant_scope as
    update iam_role_org
       set grant_scope = 'children'
     where public_id = 'r_org_2222222222';
  select lives_ok('update_grant_scope');

  select is(
    (select grant_scope_update_time is not null
       from iam_role_org
      where public_id = 'r_org_2222222222'),
    true,
    'grant_scope_update_time should be updated after changing grant_scope'
  );

  select is(
    (select grant_scope_update_time = now()
       from iam_role_org
      where public_id = 'r_org_2222222222'),
    true,
    'grant_scope_update_time should be updated after changing grant_scope'
  );

  ------------------------------------------------------------------------------
  -- 3) testing iam_role_global_individual_grant_scope table
  ------------------------------------------------------------------------------
  
  -- 3a) insert a valid row -> should succeed
  prepare update_iam_role_org_to_individual_grant_scope as
    update iam_role_org
       set grant_scope = 'individual'
     where public_id = 'r_op_sw__eng';
  select lives_ok('update_iam_role_org_to_individual_grant_scope');     

  prepare insert_valid_row as
    insert into iam_role_org_individual_grant_scope (role_id, grant_scope, scope_id)
    values ('r_op_sw__eng', 'individual', 'p____bwidget');
  select lives_ok('insert_valid_row');

  -- 3b) verify individual grant scope was inserted
  select is(
    (select count(*) from iam_role_org_individual_grant_scope
     where role_id = 'r_op_sw__eng'
       and grant_scope = 'individual'
       and scope_id = 'p____bwidget'),
    1::bigint,
    'individual grant scope was inserted'
  );

  -- 3c) verify create_time is set by trigger
  select isnt(
    (select create_time from iam_role_org_individual_grant_scope
     where role_id = 'r_op_sw__eng'
       and scope_id = 'p____bwidget'),
    null,
    'create_time should be set on insert'
  );

  -- 3d) negative test: grant_scope != 'individual'
  prepare insert_bad_grant_scope as
    insert into iam_role_org_individual_grant_scope (role_id, grant_scope, scope_id)
    values ('r_op_sw__eng', 'children', 'p____bwidget');
  select throws_like(
    'insert_bad_grant_scope',
    'new row for relation "iam_role_org_individual_grant_scope" violates check constraint "only_individual_grant_scope_allowed"',
    'grant_scope must be "individual"'
  );

  -- 3e) negative test: referencing a project scope that belongs to another org
  prepare insert_wrong_role_project as
    insert into iam_role_org_individual_grant_scope (role_id, grant_scope, scope_id)
    values ('o_____widget', 'children', 'invalid_project');
  select throws_like(
    'insert_wrong_role_project',
    'project scope_id invalid_project not found in org',
    'ensure_project_belongs_to_role_org trigger enforces matching org'
  );

  select * from finish();
rollback;
