-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

select plan(15);
select wtt_load('widgets', 'iam');

-- insert app_token_project and make sure app_token has a value
prepare insert_app_token_project as
  insert into app_token_project (
    public_id,
    scope_id,
    revoked,
    created_by_user_id,
    create_time,
    update_time,
    approximate_last_access_time,
    expiration_time
  ) values ('r_1111111111', 'p____bwidget', true, 'u_____walter', now(), now(), now(), now() + interval '7 day');
select lives_ok('insert_app_token_project');
-- ensure app_token has a value
select is(count(*), 1::bigint) from app_token where public_id = 'r_1111111111';

-- try to unrevoke a revoked app token global, should fail
prepare unrevoke_app_token_project as
  update app_token_project
  set revoked = false
  where public_id = 'r_1111111111';
select throws_like('unrevoke_app_token_project', 'App token cannot be unrevoked. Current: t, Attempted: f');

-- update the approximate_last_access_time
prepare update_approximate_last_access_time as
  update app_token_project
  set approximate_last_access_time = now() + interval '2 days'
  where public_id = 'r_1111111111';
select lives_ok('update_approximate_last_access_time');
-- ensure approximate_last_access_time was updated
select is(count(*), 1::bigint) from app_token_project
 where public_id = 'r_1111111111'
   and approximate_last_access_time > now() + interval '1 day';
-- ensure approximate_last_access_time was updated in app_token table as well
select is(count(*), 1::bigint) from app_token
 where public_id = 'r_1111111111'
   and approximate_last_access_time > now() + interval '1 day';

-- try to insert app_token_project with user that doesn't exist, should fail
prepare insert_app_token_project_invalid_user as
  insert into app_token_project (
    public_id,
    scope_id,
    created_by_user_id
  ) values ('r_2222222222', 'global', 'u_nonexistent_user');
select throws_like('insert_app_token_project_invalid_user', 'User ID u_nonexistent_user does not exist in iam_user');

-- insert app_token_permission_project
prepare insert_app_token_permission_project as
  insert into app_token_permission_project (
    private_id,
    app_token_id,
    grant_this_scope
  ) values ('p_1111111111', 'r_1111111111', 'true');
select lives_ok('insert_app_token_permission_project');
-- ensure app_token_permission has a value
select is(count(*), 1::bigint) from app_token_permission where private_id = 'p_1111111111';

-- insert app_token_permission_project with duplicate grant_scope and private_id, should fail
prepare insert_duplicate_app_token_permission_project as
  insert into app_token_permission_project (
    private_id,
    app_token_id,
    grant_this_scope
  ) values ('p_1111111111', 'r_1111111111', true);
select throws_like('insert_duplicate_app_token_permission_project', 'duplicate key value violates unique constraint "app_token_permission_pkey"');

-- delete token from app_token and ensure cascading delete to app_token_project and app_token_permission_project
prepare delete_app_token as
  delete from app_token
  where public_id = 'r_1111111111';
select lives_ok('delete_app_token');
-- ensure app_token is deleted
select is(count(*), 0::bigint) from app_token where public_id = 'r_1111111111';
-- ensure token is automatically entered in app_token_deleted
select is(count(*), 1::bigint) from app_token_deleted where public_id = 'r_1111111111';
-- ensure app_token_project is deleted
select is(count(*), 0::bigint) from app_token_project where public_id = 'r_1111111111';
-- ensure app_token_permission_project is deleted
select is(count(*), 0::bigint) from app_token_permission_project where app_token_id = 'r_1111111111';

select * from finish();
rollback;