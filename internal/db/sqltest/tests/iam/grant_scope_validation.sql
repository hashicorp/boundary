-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(27);

-- Remove any existing roles, which should also remove existing grant scopes
delete from iam_role;

-- Set up a series of scopes to test against
insert into iam_scope
    (type,      public_id,      parent_id)
values
    ('org',     'o_1111111111', 'global'),
    ('project', 'p_111111111a', 'o_1111111111'),
    ('project', 'p_111111111b', 'o_1111111111'),
    ('org',     'o_2222222222', 'global'),
    ('project', 'p_222222222a', 'o_2222222222'),
    ('project', 'p_222222222b', 'o_2222222222');

-- Insert a role at each scope
insert into iam_role
    (public_id,      scope_id) values
    ('r_globeglobe', 'global'),
    ('r_1111111111', 'o_1111111111'),
    ('r_111111111a', 'p_111111111a'),
    ('r_111111111b', 'p_111111111b'),
    ('r_2222222222', 'o_2222222222'),
    ('r_222222222a', 'p_222222222a'),
    ('r_222222222b', 'p_222222222b');

-- Start validation

-- Reset grant scopes
delete from iam_role_grant_scope;

-- Case 1a: insert the scope's own grant scope on global, org, proj
prepare insert_own_global as
    insert into iam_role_grant_scope
        (role_id,         scope_id_or_special)
    values
        ('r_globeglobe', 'global');
select lives_ok('insert_own_global');
prepare insert_own_org as
    insert into iam_role_grant_scope
        (role_id,         scope_id_or_special)
    values
        ('r_1111111111', 'o_1111111111');
select lives_ok('insert_own_org');
prepare insert_own_project as
    insert into iam_role_grant_scope
        (role_id,         scope_id_or_special)
    values
        ('r_111111111a', 'p_111111111a');
select lives_ok('insert_own_project');

-- Case 1b: with the current inserted values, ensure we can't insert "this"
prepare insert_this_fail_global as
    insert into iam_role_grant_scope
        (role_id,         scope_id_or_special)
    values
        ('r_globeglobe', 'this');
select throws_like(
    'insert_this_fail_global',
    'invalid to specify both a role''s actual scope id and "this" as a grant scope'
);
prepare insert_this_fail_org as
    insert into iam_role_grant_scope
        (role_id,         scope_id_or_special)
    values
        ('r_1111111111', 'this');
select throws_like(
    'insert_this_fail_org',
    'invalid to specify both a role''s actual scope id and "this" as a grant scope'
);
prepare insert_this_fail_project as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_111111111a', 'this');
select throws_like(
    'insert_this_fail_project',
    'invalid to specify both a role''s actual scope id and "this" as a grant scope'
);

-- Case 1c: Remove same-scope values, insert "this" for each
delete from iam_role_grant_scope;
prepare insert_this_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'this');
select lives_ok('insert_this_global');
prepare insert_this_org as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_1111111111', 'this');
select lives_ok('insert_this_org');
prepare insert_this_project as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_111111111a', 'this');
select lives_ok('insert_this_project');

-- Case 1d: Make sure with "this" that we can't insert same-scope values
prepare insert_own_fail_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'global');
select throws_like(
    'insert_own_fail_global',
    'invalid to specify both "this" and a role''s actual scope id as a grant scope'
);
prepare insert_own_fail_org as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_1111111111', 'o_1111111111');
select throws_like(
    'insert_own_fail_org',
    'invalid to specify both "this" and a role''s actual scope id as a grant scope'
);
prepare insert_own_fail_project as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_111111111a', 'p_111111111a');
select throws_like(
    'insert_own_fail_project',
    'invalid to specify both "this" and a role''s actual scope id as a grant scope'
);

-- Reset grant scopes
delete from iam_role_grant_scope;

-- Case 2a: Bare scopes that are not the role's scope succeed if descendant
prepare insert_bare_org_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'o_1111111111');
select lives_ok('insert_bare_org_global');
prepare insert_bare_proj_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'p_111111111a');
select lives_ok('insert_bare_proj_global');
prepare insert_bare_proj_org as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_1111111111', 'p_111111111a');
select lives_ok('insert_bare_proj_org');

-- Case 2b: Bare scopes that are not the role's scope fail if not descendant
prepare insert_bare_org_fail_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_1111111111', 'global');
select throws_like(
    'insert_bare_org_fail_global',
    'expected grant scope id scope type to be project'
);
prepare insert_bare_proj_fail_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_111111111a', 'global');
select throws_like(
    'insert_bare_proj_fail_global',
    'invalid to set a grant scope ID to non-same scope_id_or_special when role scope type is project'
);
prepare insert_bare_proj_fail_org as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_111111111a', 'o_1111111111');
select throws_like(
    'insert_bare_proj_fail_org',
    'invalid to set a grant scope ID to non-same scope_id_or_special when role scope type is project'
);
prepare insert_bare_proj_wrong_scope_fail_org as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_1111111111', 'p_222222222a');
select throws_like(
    'insert_bare_proj_wrong_scope_fail_org',
    'grant scope id is not a child project of the role''s org scope'
);

-- Reset grant scopes
delete from iam_role_grant_scope;

-- Case 3: "children" is only allowed in global/org
prepare insert_children_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'children');
select lives_ok('insert_children_global');
prepare insert_children_org as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_1111111111', 'children');
select lives_ok('insert_children_org');
prepare insert_children_fail_proj as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_111111111a', 'children');
select throws_like(
    'insert_children_fail_proj',
    'invalid to set a grant scope ID to non-same scope_id_or_special when role scope type is project'
);

-- Reset grant scopes
delete from iam_role_grant_scope;

-- Case 4: "descendants" is only allowed in global
prepare insert_descendants_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'descendants');
select lives_ok('insert_descendants_global');
prepare insert_descendants_fail_org as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_1111111111', 'descendants');
select throws_like(
    'insert_descendants_fail_org',
    'invalid to specify "descendants" as a grant scope when the role''s scope ID is not "global"'
);
prepare insert_descendants_fail_proj as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_111111111a', 'descendants');
select throws_like(
    'insert_descendants_fail_proj',
    'invalid to set a grant scope ID to non-same scope_id_or_special when role scope type is project'
);

-- Reset grant scopes
delete from iam_role_grant_scope;

-- Case 5: "descendants" and "children" are mutually exclusive
prepare insert_descendants_and_children_fail_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'descendants'),
        ('r_globeglobe', 'children');
select throws_like(
    'insert_descendants_and_children_fail_global',
    'invalid to specify both "descendants" and "children" as a grant scope'
);
prepare insert_children_and_descendants_fail_global as
    insert into iam_role_grant_scope
        (role_id,        scope_id_or_special)
    values
        ('r_globeglobe', 'children'),
        ('r_globeglobe', 'descendants');
select throws_like(
    'insert_children_and_descendants_fail_global',
    'invalid to specify both "children" and "descendants" as a grant scope'
);

select * from finish();
rollback;
