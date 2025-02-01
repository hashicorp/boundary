-- copyright (c) hashicorp, inc.
-- spdx-license-identifier: busl-1.1

begin;
select plan(9);
select wtt_load('widgets', 'iam');

prepare insert_grant_scope as
  insert into iam_grant
    (canonical_grant)
  values
    ('type=scope;others=stuff;');

select lives_ok('insert_grant_scope');

select is(
  (select resource
     from iam_grant
    where canonical_grant = 'type=scope;others=stuff;'),
  'scope',
  'resource should be set to "scope" by set_resource() trigger'
);

prepare insert_grant_no_type as
  insert into iam_grant
    (canonical_grant)
  values
    ('no_type_at_all;');

select lives_ok('insert_grant_no_type');

select is(
  (select resource
     from iam_grant
    where canonical_grant = 'no_type_at_all;'),
  'unknown',
  'resource should default to "unknown" if type=... is not found'
);

prepare insert_grant_role as
  insert into iam_grant
    (canonical_grant)
  values
    ('type=role;foo=bar;');
select lives_ok('insert_grant_role');

select is(
  (select resource
     from iam_grant
    where canonical_grant = 'type=role;foo=bar;'),
  'role',
  'resource should be set to "role"'
);

-- the set_resource() trigger will set resource='bogus', but we did not insert 'bogus'
-- into resource_enm, so it should fail.
prepare insert_grant_bogus as
  insert into iam_grant
    (canonical_grant)
  values
    ('type=bogus;some=thing;');
select throws_like(
  'insert_grant_bogus',
  'insert or update on table "iam_grant" violates foreign key constraint "resource_enm_fkey"',
  'inserting a resource not in resource_enm should fail'
);

prepare insert_dup_grant_1 as
  insert into iam_grant
    (canonical_grant)
  values
    ('duplicate_grant;type=scope;');
select lives_ok('insert_dup_grant_1');

prepare insert_dup_grant_2 as
  insert into iam_grant
    (canonical_grant)
  values
    ('duplicate_grant;type=scope;');
select throws_like(
  'insert_dup_grant_2',
  'duplicate key value violates unique constraint "iam_grant_pkey"',
  'primary key (canonical_grant) is enforced'
);

select * from finish();
rollback;
