-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

select plan(16);
select wtt_load('widgets', 'iam');

-- insert app_token_org and make sure app_token has a value
prepare insert_app_token_org as
  insert into app_token_org (
    public_id,
    scope_id,
    revoked,
    created_by_user_id,
    create_time,
    update_time,
    approximate_last_access_time,
    expiration_time
  ) values ('r_1111111111', 'o_____widget', true, 'u_____walter', now(), now(), now(), now() + interval '1 day');
select lives_ok('insert_app_token_org');
-- ensure app_token has a value
select is(count(*), 1::bigint) from app_token where public_id = 'r_1111111111';

-- try to unrevoke a revoked app token org, should fail
prepare unrevoke_app_token_org as
  update app_token_org
  set revoked = false
  where public_id = 'r_1111111111';
select throws_like('unrevoke_app_token_org', 'App token cannot be unrevoked. revoked value. Current: t, Attempted: f');

-- try to insert app_token_org with user that doesn't exist, should fail
prepare insert_app_token_org_invalid_user as
  insert into app_token_org (
    public_id,
    scope_id,
    created_by_user_id
  ) values ('r_2222222222', 'o_____widget', 'u_nonexistent_user');
select throws_like('insert_app_token_org_invalid_user', 'User ID u_nonexistent_user does not exist in iam_user');

-- insert app_token_permission_org
prepare insert_app_token_permission_org as
  insert into app_token_permission_org (
    private_id,
    app_token_id,
    grant_scope,
    create_time
  ) values ('p_1111111111', 'r_1111111111', 'individual', now());
select lives_ok('insert_app_token_permission_org');
-- ensure app_token_permission has a value
select is(count(*), 1::bigint) from app_token_permission where private_id = 'p_1111111111';

-- insert app_token_permission_org with duplicate grant_scope and private_id, should fail
prepare insert_duplicate_app_token_permission_org as
  insert into app_token_permission_org (
    private_id,
    app_token_id,
    grant_scope,
    create_time
  ) values ('p_1111111111', 'r_1111111111', 'individual', now());
select throws_like('insert_duplicate_app_token_permission_org', 'duplicate key value violates unique constraint "app_token_permission_pkey"');

-- insert app_token_permission_org_individual_grant_scope with:
-- individual grant_scope, permission_id that exists in app_token_permission_org, valid org scope id
prepare insert_app_token_permission_org_individual_grant_scope as
  insert into app_token_permission_org_individual_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'p____bwidget', 'individual');
select lives_ok('insert_app_token_permission_org_individual_grant_scope');

-- insert app_token_permission_org_individual_grant_scope with:
-- individual grant_scope, permission_id that does not exist in app_token_permission_org, valid org scope id
-- should fail
prepare insert_app_token_poi_grant_scope_invalid_permission_id as
  insert into app_token_permission_org_individual_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_nonexistent_permission', 'p____bwidget', 'individual');
select throws_like('insert_app_token_poi_grant_scope_invalid_permission_id',
  'permission_id p_nonexistent_permission not found or has no associated app token');

-- insert app_token_permission_org_individual_grant_scope with:
-- non-individual grant_scope, permission_id that exists in app_token_permission_org, valid org scope id
-- should fail
prepare insert_app_token_poi_grant_scope_invalid_grant_scope as
  insert into app_token_permission_org_individual_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'p____bwidget', 'children');
select throws_like('insert_app_token_poi_grant_scope_invalid_grant_scope',
  'new row for relation "app_token_permission_org_individual_grant_scope" violates check constraint "only_individual_grant_scope_allowed"');

-- insert app_token_permission_org_individual_grant_scope with:
-- individual grant_scope, permission_id that exists in app_token_permission_org, invalid org scope id
-- should fail
prepare insert_app_token_pgi_org_grant_scope_invalid_scope_id as
  insert into app_token_permission_org_individual_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'p_nonexistent_scope', 'individual');
select throws_like('insert_app_token_pgi_org_grant_scope_invalid_scope_id',
  'project scope_id p_nonexistent_scope not found or is not a child of org o_____widget');

-- delete token from app_token and ensure cascading delete to app_token_org and app_token_permission_org
prepare delete_app_token as
  delete from app_token
  where public_id = 'r_1111111111';
select lives_ok('delete_app_token');
-- ensure app_token is deleted
select is(count(*), 0::bigint) from app_token where public_id = 'r_1111111111';
-- ensure token is automatically entered in app_token_deleted
select is(count(*), 1::bigint) from app_token_deleted where public_id = 'r_1111111111';
-- ensure app_token_org is deleted
select is(count(*), 0::bigint) from app_token_org where public_id = 'r_1111111111';
-- ensure app_token_permission_org is deleted
select is(count(*), 0::bigint) from app_token_permission_org where app_token_id = 'r_1111111111';

select * from finish();
rollback;