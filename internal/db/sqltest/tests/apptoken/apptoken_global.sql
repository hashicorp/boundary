-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

select plan(30);
select wtt_load('widgets', 'iam');

-- insert app_token_global and make sure app_token has a value
prepare insert_app_token_global as
  insert into app_token_global (
    public_id,
    scope_id,
    revoked,
    created_by_user_id,
    create_time,
    update_time,
    approximate_last_access_time,
    expiration_time
  ) values ('appt_1111111111', 'global', true, 'u_____walter', now(), now(), now(), now() + interval '7 day');
select lives_ok('insert_app_token_global');
-- ensure app_token has a value
select is(count(*), 1::bigint) from app_token where public_id = 'appt_1111111111';

-- try to unrevoke a revoked app token global, should fail
prepare unrevoke_app_token_global as
  update app_token_global
  set revoked = false
  where public_id = 'appt_1111111111';
select throws_like('unrevoke_app_token_global', 'App token cannot be unrevoked. Current: t, Attempted: f');

-- update the approximate_last_access_time
prepare update_approximate_last_access_time as
  update app_token_global
  set approximate_last_access_time = now() + interval '2 days'
  where public_id = 'appt_1111111111';
select lives_ok('update_approximate_last_access_time');
-- ensure approximate_last_access_time was updated
select is(count(*), 1::bigint) from app_token_global
 where public_id = 'appt_1111111111'
   and approximate_last_access_time > now() + interval '1 day';
-- ensure approximate_last_access_time was updated in app_token table as well
select is(count(*), 1::bigint) from app_token
 where public_id = 'appt_1111111111'
   and approximate_last_access_time > now() + interval '1 day';

-- insert into app_token_cipher table for the app token
prepare insert_app_token_cipher as
  insert into app_token_cipher (
    app_token_id,
    key_id,
    token
  ) values ('appt_1111111111', 'kdkv__colors', 'ciphertext_example');
select lives_ok('insert_app_token_cipher');
-- ensure app_token_cipher has a value
select is(count(*), 1::bigint) from app_token_cipher where app_token_id = 'appt_1111111111';

-- insert into app_token_cipher with non-existent app_token_id, should fail
prepare insert_app_token_cipher_invalid_token as
  insert into app_token_cipher (
    app_token_id,
    key_id,
    token
  ) values ('r_does_not_exist', 'kdkv__colors', 'ciphertext_two');
select throws_like('insert_app_token_cipher_invalid_token',
  'insert or update on table "app_token_cipher" violates foreign key constraint "app_token_cipher_app_token_fkey"');

-- insert into app_token_cipher with duplicate app_token_id, should fail
prepare insert_duplicate_app_token_cipher as
  insert into app_token_cipher (
    app_token_id,
    key_id,
    token
  ) values ('appt_1111111111', 'kdkv__colors', 'ciphertext_three');
select throws_like('insert_duplicate_app_token_cipher',
  'duplicate key value violates unique constraint "app_token_cipher_pkey"');

-- insert app_token_cipher with duplicate token but different app_token_id, should fail
prepare insert_app_token_cipher_duplicate_token as
  insert into app_token_cipher (
    app_token_id,
    key_id,
    token
  ) values ('r_2222222222', 'kdkv__colors', 'ciphertext_example');
select throws_like('insert_app_token_cipher_duplicate_token',
  'duplicate key value violates unique constraint "app_token_cipher_token_key"');

-- try to insert app_token_global with user that doesn't exist, should fail
prepare insert_app_token_global_invalid_user as
  insert into app_token_global (
    public_id,
    scope_id,
    created_by_user_id
  ) values ('r_2222222222', 'global', 'u_nonexistent_user');
select throws_like('insert_app_token_global_invalid_user', 'User ID u_nonexistent_user does not exist in iam_user');

-- insert app_token_permission_global
prepare insert_app_token_permission_global as
  insert into app_token_permission_global (
    private_id,
    app_token_id,
    grant_scope
  ) values ('p_1111111111', 'appt_1111111111', 'individual');
select lives_ok('insert_app_token_permission_global');
-- ensure app_token_permission has a value
select is(count(*), 1::bigint) from app_token_permission where private_id = 'p_1111111111';

-- insert app_token_permission_global with duplicate grant_scope and private_id, should fail
prepare insert_duplicate_app_token_permission_global as
  insert into app_token_permission_global (
    private_id,
    app_token_id,
    grant_scope
  ) values ('p_1111111111', 'appt_1111111111', 'individual');
select throws_like('insert_duplicate_app_token_permission_global', 'duplicate key value violates unique constraint "app_token_permission_pkey"');

-- insert app_token_permission_global with descendant grant_scope and private_id, should fail
prepare insert_descendant_app_token_permission_global as
  insert into app_token_permission_global (
    private_id,
    app_token_id,
    grant_scope
  ) values ('p_1111111111', 'p____bwidget', 'descendant');
select throws_like('insert_descendant_app_token_permission_global', 'duplicate key value violates unique constraint "app_token_permission_pkey"');

-- insert app_token_permission_global with children grant_scope and private_id, should fail
prepare insert_children_app_token_permission_global as
  insert into app_token_permission_global (
    private_id,
    app_token_id,
    grant_scope
  ) values ('p_1111111111', 'o_____widget', 'children');
select throws_like('insert_children_app_token_permission_global', 'duplicate key value violates unique constraint "app_token_permission_pkey"');

-- insert app_token_permission_global_individual_org_grant_scope with:
-- individual grant_scope, permission_id that exists in app_token_permission_global, valid org scope id
prepare insert_app_token_permission_global_individual_org_grant_scope as
  insert into app_token_permission_global_individual_org_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'o_____widget', 'individual');
select lives_ok('insert_app_token_permission_global_individual_org_grant_scope');

-- insert app_token_permission_global_individual_org_grant_scope with:
-- individual grant_scope, permission_id that does not exist in app_token_permission_global, valid org scope id
-- should fail
prepare insert_app_token_pgi_org_grant_scope_invalid_permission_id as
  insert into app_token_permission_global_individual_org_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_nonexistent_permission', 'o_____widget', 'individual');
select throws_like('insert_app_token_pgi_org_grant_scope_invalid_permission_id',
  'insert or update on table "app_token_permission_global_individual_org_grant_scope" violates foreign key constraint "app_token_permission_global_fkey"');

-- insert app_token_permission_global_individual_org_grant_scope with:
-- non-individual grant_scope, permission_id that exists in app_token_permission_global, valid org scope id
-- should fail
prepare insert_app_token_pgi_org_grant_scope_invalid_grant_scope as
  insert into app_token_permission_global_individual_org_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'o_____widget', 'children');
select throws_like('insert_app_token_pgi_org_grant_scope_invalid_grant_scope',
  'new row for relation "app_token_permission_global_individual_org_grant_scope" violates check constraint "only_individual_grant_scope_allowed"');

-- insert app_token_permission_global_individual_org_grant_scope with:
-- individual grant_scope, permission_id that exists in app_token_permission_global, invalid org scope id
-- should fail
prepare insert_app_token_pgi_org_grant_scope_invalid_scope_id as
  insert into app_token_permission_global_individual_org_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'p_nonexistent_scope', 'individual');
select throws_like('insert_app_token_pgi_org_grant_scope_invalid_scope_id',
  'org scope_id p_nonexistent_scope not found');

-- insert app_token_permission_global_individual_project_grant_scope with:
-- individual grant_scope, permission_id that exists in app_token_permission_global, valid project scope id
prepare insert_app_token_pgi_project_grant_scope as
  insert into app_token_permission_global_individual_project_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'p____bwidget', 'individual');
select lives_ok('insert_app_token_pgi_project_grant_scope');

-- insert app_token_permission_global_individual_project_grant_scope with:
-- individual grant_scope, permission_id that does not exist in app_token_permission_global, valid project scope id
-- should fail
prepare insert_app_token_pgi_project_grant_scope_invalid_permission_id as
  insert into app_token_permission_global_individual_project_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_nonexistent_permission', 'p____bwidget', 'individual');
select throws_like('insert_app_token_pgi_project_grant_scope_invalid_permission_id',
  'insert or update on table "app_token_permission_global_individual_project_grant_scope" violates foreign key constraint "app_token_permission_global_fkey"');

-- insert duplicate app_token_permission_global_individual_project_grant_scope with:
-- different grant_scope, permission_id that exists in app_token_permission_global, valid project scope id
-- should fail
prepare insert_duplicate_app_token_pgi_project_grant_scope as
  insert into app_token_permission_global_individual_project_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'p____bwidget', 'children');
select throws_like('insert_duplicate_app_token_pgi_project_grant_scope',
  'duplicate key value violates unique constraint "app_token_permission_global_individual_project_grant_scope_pkey"');

-- insert app_token_permission_global_individual_project_grant_scope with:
-- individual grant_scope, permission_id that exists in app_token_permission_global, invalid project scope id
-- should fail
prepare insert_app_token_pgi_project_grant_scope_invalid_scope_id as
  insert into app_token_permission_global_individual_project_grant_scope (
    permission_id,
    scope_id,
    grant_scope
  ) values ('p_1111111111', 'p_nonexistent_scope', 'individual');
select throws_like('insert_app_token_pgi_project_grant_scope_invalid_scope_id',
  'project scope_id p_nonexistent_scope not found');

-- delete token from app_token and ensure cascading delete to app_token_global and app_token_permission_global
prepare delete_app_token as
  delete from app_token
  where public_id = 'appt_1111111111';
select lives_ok('delete_app_token');
-- ensure app_token is deleted
select is(count(*), 0::bigint) from app_token where public_id = 'appt_1111111111';
-- ensure token is automatically entered in app_token_deleted
select is(count(*), 1::bigint) from app_token_deleted where public_id = 'appt_1111111111';
-- ensure app_token_global is deleted
select is(count(*), 0::bigint) from app_token_global where public_id = 'appt_1111111111';
-- ensure app_token_permission_global is deleted
select is(count(*), 0::bigint) from app_token_permission_global where app_token_id = 'appt_1111111111';

select * from finish();
rollback;