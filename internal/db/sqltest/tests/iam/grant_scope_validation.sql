-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(13);

-- Remove any existing roles, which should also remove existing grant scopes
delete from iam_role;

-- Set up a series of scopes to test against
insert into iam_scope (type, public_id, parent_id) values
    ('org', 'o_1111111111', 'global'),
    ('project', 'p_111111111a', 'o_1111111111'),
    ('project', 'p_111111111b', 'o_1111111111'),
    ('org', 'o_2222222222', 'global'),
    ('project', 'p_222222222a', 'o_2222222222'),
    ('project', 'p_222222222b', 'o_2222222222');

-- Insert a role at each scope
insert into iam_role (public_id, scope_id) values
    ('r_globeglobe', 'global'),
    ('r_1111111111', 'o_1111111111'),
    ('r_111111111a', 'p_111111111a'),
    ('r_111111111b', 'p_111111111b'),
    ('r_2222222222', 'o_2222222222'),
    ('r_222222222a', 'p_222222222a'),
    ('r_222222222b', 'p_222222222b');

-- Start validation
-- Verify we are starting from no grant scopes
select is(count(*), 0::bigint) from iam_role_grant_scope;

-- Case 1a: insert the scope's own grant scope on global, org, proj
prepare insert_own_global as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_globeglobe', 'global');
select lives_ok('insert_own_global');
prepare insert_own_org as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_1111111111', 'o_1111111111');
select lives_ok('insert_own_org');
prepare insert_own_project as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_111111111a', 'p_111111111a');
select lives_ok('insert_own_project');

-- Case 1b: with the current inserted values, ensure we can't insert "this"
prepare insert_this_fail_global as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_globeglobe', 'this');
select throws_ok(
    'insert_this_fail_global',
    null,
    'invalid to specify both a role''s actual scope id and "this" as a grant scope'
);
prepare insert_this_fail_org as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_1111111111', 'this');
select throws_ok(
    'insert_this_fail_org',
    null,
    'invalid to specify both a role''s actual scope id and "this" as a grant scope'
);
prepare insert_this_fail_project as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_111111111a', 'this');
select throws_ok(
    'insert_this_fail_project',
    null,
    'invalid to specify both a role''s actual scope id and "this" as a grant scope'
);

-- Case 1c: Remove same-scope values, insert "this" for each
delete from iam_role_grant_scope;
prepare insert_this_global as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_globeglobe', 'this');
select lives_ok('insert_this_global');
prepare insert_this_org as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_1111111111', 'this');
select lives_ok('insert_this_org');
prepare insert_this_project as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_111111111a', 'this');
select lives_ok('insert_this_project');

-- Case 1d: Make sure with "this" that we can't insert same-scope values
prepare insert_own_fail_global as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_globeglobe', 'global');
select throws_ok(
    'insert_own_fail_global',
    null,
    'invalid to specify both "this" and a role''s actual scope id as a grant scope'
);
prepare insert_own_fail_org as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_1111111111', 'o_1111111111');
select throws_ok(
    'insert_own_fail_org',
    null,
    'invalid to specify both "this" and a role''s actual scope id as a grant scope'
);
prepare insert_own_fail_project as
    insert into iam_role_grant_scope
        (role_id, scope_id_or_special)
    values
        ('r_111111111a', 'p_111111111a');
select throws_ok(
    'insert_own_fail_project',
    null,
    'invalid to specify both "this" and a role''s actual scope id as a grant scope'
);

select * from finish();
rollback;
