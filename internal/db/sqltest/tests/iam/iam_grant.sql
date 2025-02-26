-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(31);
select wtt_load('widgets', 'iam');

-- insert canonical_grant with valid resource
-- validate the resource is set to 'scope'
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

-- insert canonical_grant with no type
-- validate the resource is set to 'unknown'
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
  'resource should default to "unknown" if type is not found'
);

-- insert canonical_grant with type=role,group
-- validate the resource is set to 'role'
prepare insert_grant_role as
  insert into iam_grant
    (canonical_grant)
  values
    ('type=role,group;foo=bar;');
select throws_like(
  'insert_grant_role',
  'insert or update on table "iam_grant" violates foreign key constraint "iam_grant_resource_enm_fkey"',
  'inserting a resource not in iam_grant_resource_enm should fail because type is not a single value'
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
  'insert or update on table "iam_grant" violates foreign key constraint "iam_grant_resource_enm_fkey"',
  'inserting a resource not in iam_grant_resource_enm should fail'
);

-- insert a duplicate canonical_grant
-- validate that the primary key constraint is enforced
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

-- insert a canonical grant string with wildcards for id, type, actions, and output_fields
-- validate that the resource is set to '*'
prepare insert_grant_wildcard as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type=*;actions=*;output_fields=*');
select lives_ok('insert_grant_wildcard');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;type=*;actions=*;output_fields=*'),
  '*',
  'resource should be set to "*" if type is "*"'
);

-- insert a canonical grant string with single action, single id, single output_field and type=host
-- validate that the resource is set to 'host'
prepare insert_grant_single_action as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=o_1234;type=host;actions=create;output_fields=id');
select lives_ok('insert_grant_single_action');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=o_1234;type=host;actions=create;output_fields=id'),
  'host',
  'resource should be set to "host" if type is "host"'
);

-- insert a canonical grant string with type=group, multiple actions, single type and multiple output_fields
-- validate that the resource is set to 'group'
prepare insert_grant_role_multiple_actions as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=o_1234,o_4567;type=group;actions=create,update;output_fields=id,name');
select lives_ok('insert_grant_role_multiple_actions');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=o_1234,o_4567;type=group;actions=create,update;output_fields=id,name'),
  'group',
  'resource should be set to "group" if type is "group"'
);

-- insert a canonical grant string with with multiple types
-- the insert should fail because the resource is not a single value
prepare insert_grant_multiple_types as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=o_1234,o_4567;type=target,role,group;actions=create,update;output_fields=id,name');
select throws_like(
  'insert_grant_multiple_types',
  'insert or update on table "iam_grant" violates foreign key constraint "iam_grant_resource_enm_fkey"',
  'inserting a resource not in iam_grant_resource_enm should fail because type is not a single value'
);

-- insert a canonical grant string with type with dash
-- validate that the resource is set to 'credential-library'
prepare insert_grant_with_dash as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type=credential-library;actions=create;output_fields=id');
select lives_ok('insert_grant_with_dash');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;type=credential-library;actions=create;output_fields=id'),
  'credential-library',
  'resource should be set to "credential-library" if type is "credential-library"'
);

-- insert a canonical grant string with type with underscore
-- the insert should fail because a resource with underscore is not in the resource_enm table
prepare insert_grant_with_underscore as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type=credential_library;actions=create;output_fields=id');
select throws_like(
  'insert_grant_with_underscore',
  'insert or update on table "iam_grant" violates foreign key constraint "iam_grant_resource_enm_fkey"',
  'inserting a a resource with underscore should fail'
);

-- insert a canonical grant string with type malformed with no semicolon
-- the insert should fail because the type is malformed
prepare insert_grant_malformed_type_with_no_semicolon as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type=credential-library actions=create;output_fields=id');
select throws_like(
  'insert_grant_malformed_type_with_no_semicolon',
  'insert or update on table "iam_grant" violates foreign key constraint "iam_grant_resource_enm_fkey"',
  'inserting a resource with a malformed type should fail'
);

-- insert a canonical grant string with type malformed with no equals sign
prepare insert_grant_malformed_type_with_no_equals as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type;actions=create;output_fields=id');
select lives_ok('insert_grant_malformed_type_with_no_equals');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;type;actions=create;output_fields=id'),
  'unknown',
  'resource should default to "unknown" if the type has no equals sign'
);

-- insert a canonical grant string with type malformed with no value
prepare insert_grant_malformed_type_with_no_value as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type=;actions=create;output_fields=id');
select lives_ok('insert_grant_malformed_type_with_no_value');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;type=;actions=create;output_fields=id'),
  'unknown',
  'resource should default to "unknown" if the type has no value'
);

-- insert a canonical grant string with type malformed with no type
prepare insert_grant_malformed_type_with_no_type as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;actions=create;output_fields=id');
select lives_ok('insert_grant_malformed_type_with_no_type');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;actions=create;output_fields=id'),
  'unknown',
  'resource should default to "unknown" if the type is not found'
);

-- insert a canonical grant string with type malformed with double ids semicolon
prepare insert_grant_malformed_type_with_double_ids_semicolon as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;;type=credential-library;actions=create;output_fields=id');
select lives_ok('insert_grant_malformed_type_with_double_ids_semicolon');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;;type=credential-library;actions=create;output_fields=id'),
  'credential-library',
  'resource should be set to "credential-library"'
);

-- insert a canonical grant string with type at the end of the string
prepare insert_grant_malformed_type_with_type_at_the_end as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;actions=create;output_fields=id;type=credential-library');
select lives_ok('insert_grant_malformed_type_with_type_at_the_end');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;actions=create;output_fields=id;type=credential-library'),
  'unknown',
  'resource should default to "unknown" if the type is not in the expected order'
);

-- insert a canonical grant string with type malformed with semicolon after type
prepare insert_grant_malformed_type_with_semicolon_after_type as
  insert into iam_grant
    (canonical_grant)
  values
    ('ids=*;type;=credential-library;actions=create;output_fields=id;');
select lives_ok('insert_grant_malformed_type_with_semicolon_after_type');
select is(
  (select resource
     from iam_grant
    where canonical_grant = 'ids=*;type;=credential-library;actions=create;output_fields=id;'),
  'unknown',
  'resource should default to "unknown" if the type is not found'
);

select * from finish();
rollback;
