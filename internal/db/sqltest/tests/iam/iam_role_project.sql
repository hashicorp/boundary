-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(14);
select wtt_load('widgets', 'iam');

--------------------------------------------------------------------------------
-- 1) test valid inserts
--------------------------------------------------------------------------------
prepare insert_valid_project_role as
    insert into iam_role_project
        (public_id, scope_id)
    values
        ('r_proj_1111111111', 'p____bwidget');

select lives_ok('insert_valid_project_role');

-- verify the row actually got inserted in iam_role_project
select is(
  (select count(*) from iam_role_project where public_id = 'r_proj_1111111111'),
  1::bigint,
  'one valid row inserted into iam_role_project'
);

-- check that insert_role_subtype trigger created a corresponding row in iam_role
select is(
  (select count(*) from iam_role where public_id = 'r_proj_1111111111'),
  1::bigint,
  'insert_role_subtype trigger inserted a row into iam_role'
);

-- verify create_time is set (default_create_time_column trigger)
select isnt(
  (select create_time from iam_role_project where public_id = 'r_proj_1111111111'),
  null,
  'create_time is auto-set on insert'
);

--------------------------------------------------------------------------------
-- 2) test invalid inserts
--------------------------------------------------------------------------------

-- 2a) invalid project scope (not in iam_scope_project)
prepare insert_invalid_scope as
  insert into iam_role_project 
    (public_id, scope_id)
  values
    ('r_proj_2222222222', 'o_1111111111');
select throws_like(
  'insert_invalid_scope',
  'insert or update on table "iam_role" violates foreign key constraint "iam_scope_scope_id_fkey"',
  'must reference a valid project scope'
);

-- 2b) duplicate primary ke
prepare insert_duplicate_role_id as
  insert into iam_role_project
    (public_id, scope_id)
  values
    ('r_proj_1111111111', 'p____bwidget');
select throws_like(
  'insert_duplicate_role_id',
  'duplicate key value violates unique constraint "iam_role_pkey"',
  'primary key (public_id) is enforced'
);

--------------------------------------------------------------------------------
-- 3) test triggers for immutable_columns
--------------------------------------------------------------------------------

-- 3a) try updating immutable columns: scope_id, create_time
prepare update_scope_id as
  update iam_role_project
     set scope_id = 'p____bwidget2'
   where public_id = 'r_proj_1111111111';
select throws_like(
  'update_scope_id',
  'immutable column: iam_role_project.scope_id',
  'immutable_columns trigger prevents changing scope_id'
);

prepare update_create_time as
  update iam_role_project
     set create_time = null
   where public_id = 'r_proj_1111111111';
select throws_like(
  'update_create_time',
  'immutable column: iam_role_project.create_time',
  'immutable_columns trigger prevents changing create_time'
);

  ------------------------------------------------------------------------------
  -- 4) testing grant_scope_update_time trigger
  ------------------------------------------------------------------------------

  -- 4a) insert a row -> expect it to set grant_scope_update_time (if triggered on insert)
  prepare insert_with_grant_this_role_scope_update_time as
    insert into iam_role_project
      (public_id, scope_id, grant_this_role_scope, grant_this_role_scope_update_time)
    values
      ('r_proj_22222222', 'p____bwidget', false, null);
  select lives_ok('insert_with_grant_this_role_scope_update_time');

  select is(
    (select grant_this_role_scope_update_time is not null
       from iam_role_project
      where public_id = 'r_proj_22222222'),
    true,
    'grant_this_role_scope_update_time should be set right after insert if the trigger sets it'
  );

  -- 4b) update grant_this_role_scope => trigger should update grant_this_role_scope_update_time

  -- update grant_this_role_scope_update_time to default
  prepare reset_grant_this_role_scope_update_time as
    update iam_role_project
       set grant_this_role_scope_update_time = '1970-01-01 00:00:00'
     where public_id = 'r_proj_22222222';
  select lives_ok('reset_grant_this_role_scope_update_time');

  prepare update_grant_this_role_scope as
    update iam_role_project
       set grant_this_role_scope = true
     where public_id = 'r_proj_22222222';
  select lives_ok('update_grant_this_role_scope');

  select is(
    (select grant_this_role_scope_update_time is not null
       from iam_role_project
      where public_id = 'r_proj_22222222'),
    true,
    'grant_this_role_scope_update_time should be updated after changing grant_this_role_scope'
  );

  select is(
    (select grant_this_role_scope_update_time = now()
       from iam_role_project
      where public_id = 'r_proj_22222222'),
    true,
    'grant_this_role_scope_update_time should be updated after changing grant_this_role_scope'
  );

select * from finish();
rollback;
