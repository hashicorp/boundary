-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Create the enumeration table for the grant scope types for the global iam_role
  create table iam_role_global_grant_scope_enm (
    name text primary key
      constraint only_predefined_scope_types_allowed
        check(
          name in (
            'descendants',
            'children',
            'individual'
          )
        )
  );
  comment on table iam_role_global_grant_scope_enm is
    'iam_role_global_grant_scope_enm is an enumeration table for role grant scope types for the iam_role_global table.';

  -- global iam_role must have a scope_id of global.
  --
  -- grant_this_role_scope indicates if the role can apply its grants to the scope.
  -- grant_scope indicates the scope of the grants. 
  -- grant_scope can be 'descendants', 'children', or 'individual'.
  --
  -- grant_this_role_scope_update_time and grant_scope_update_time are used to track 
  -- the last time the grant_this_role_scope and grant_scope columns were updated.
  -- This is used to represent the grant scope create_time column from the 
  -- iam_role_grant_scope table in 83/01_iam_role_grant_scope.up.sql.
  -- This matches the representation of the existing create_time field at the 
  -- role domain layer that indicates when the grant scope was created.
  create table iam_role_global (
    public_id wt_role_id primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_global_fkey
        references iam_scope_global(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    grant_this_role_scope boolean not null default false,
    grant_scope text not null
      constraint iam_role_global_grant_scope_enm_fkey
        references iam_role_global_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    version wt_version,
    grant_this_role_scope_update_time wt_timestamp,
    grant_scope_update_time wt_timestamp,
    create_time wt_timestamp,
    update_time wt_timestamp,
    constraint iam_role_global_grant_scope_public_id_uq
      unique(grant_scope, public_id),
    constraint iam_role_global_name_scope_id_uq
      unique(name, scope_id)
  );
  comment on table iam_role_global is
    'iam_role_global is the subtype table for the global role. grant_this_role_scope_update_time and grant_scope_update_time are used to track the last time the grant_this_role_scope and grant_scope columns were updated.';

  create table iam_role_global_individual_org_grant_scope (
    role_id wt_role_id
      constraint iam_role_global_fkey
        references iam_role_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the iam_role_global
    -- grant_scope, it ensures that iam_role_global is set to 'individual'
    -- if this table is populated for the corresponding role.
    grant_scope text not null
       constraint only_individual_grant_scope_allowed
         check(
          grant_scope = 'individual'
        ), 
    constraint iam_role_global_grant_scope_fkey
      foreign key (role_id, grant_scope)
      references iam_role_global(public_id, grant_scope)
      on delete cascade
      on update cascade,
    create_time wt_timestamp,
    primary key(role_id, scope_id)
  );
  comment on table iam_role_global_individual_org_grant_scope is
    'iam_role_global_individual_org_grant_scope is a list of individually granted org scope to global roles with grant_scope of individual.';

  create table iam_role_global_individual_project_grant_scope (
    role_id wt_role_id
      constraint iam_role_global_fkey
        references iam_role_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the iam_role_global
    -- grant_scope, it ensures that iam_role_global is set to 'individual'
    -- if this table is populated for the corresponding role.
    -- both children and individual are allowed for this global role
    -- because projects can be individually in addition to children 
    -- which grants all orgs
    grant_scope text not null
       constraint only_individual_or_children_grant_scope_allowed
         check(
          grant_scope in ('individual', 'children')
        ),
    constraint iam_role_global_grant_scope_fkey
      foreign key (role_id, grant_scope)
      references iam_role_global(public_id, grant_scope)
      on delete cascade
      on update cascade,
    create_time wt_timestamp,
    primary key(role_id, scope_id)
  );
  comment on table iam_role_global_individual_project_grant_scope is
    'iam_role_global_individual_project_grant_scope is a list of individually granted project scope table to global role with grant_scope of individual or children.';

  -- Create the enumeration table for the grant scope types for the org iam_role
  create table iam_role_org_grant_scope_enm (
    name text primary key
      constraint only_predefined_scope_types_allowed
        check(
          name in (
            'children',
            'individual'
          )
        )
  );
  comment on table iam_role_org_grant_scope_enm is
  'iam_role_org_grant_scope_enm is an enumeration table for role grant scope types for the iam_role_org table.';

  create table iam_role_org (
    public_id wt_role_id primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    grant_this_role_scope boolean not null default false,
    grant_scope text not null
      constraint iam_role_org_grant_scope_enm_fkey
        references iam_role_org_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    version wt_version,
    grant_this_role_scope_update_time wt_timestamp,
    grant_scope_update_time wt_timestamp,
    create_time wt_timestamp,
    update_time wt_timestamp,
    constraint iam_role_org_grant_scope_public_id_uq
      unique(grant_scope, public_id),
    constraint iam_role_org_name_scope_id_uq
      unique(name, scope_id)
  );
  comment on table iam_role_org is
    'iam_role_org is a subtype table of the iam_role table. It is used to store roles that are scoped to an org.';

  create table iam_role_org_individual_grant_scope (
    role_id wt_role_id
      constraint iam_role_org_fkey
        references iam_role_org(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the iam_role_org
    -- grant_scope, it ensures that iam_role_org is set to 'individual'
    -- if this table is populated for the corresponding role.
    grant_scope text not null
      constraint only_individual_grant_scope_allowed
        check(
            grant_scope = 'individual'
        ),
    constraint iam_role_org_grant_scope_fkey 
      foreign key (role_id, grant_scope)
      references iam_role_org(public_id, grant_scope)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    primary key(role_id, scope_id)
  );
  comment on table iam_role_org_individual_grant_scope is
    'iam_role_org_individual_grant_scope is a list of individually granted project scope to org roles with grant_scope of individual';

  create table iam_role_project (
    public_id wt_role_id primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    grant_this_role_scope boolean not null default false,
    version wt_version,
    grant_this_role_scope_update_time wt_timestamp,
    create_time wt_timestamp,
    update_time wt_timestamp,
    constraint iam_role_project_name_scope_id_uq
        unique(name, scope_id)
  );
  comment on table iam_role_project is
    'iam_role_project is a subtype table of the iam_role table. It is used to store roles that are scoped to a project.';

  create table iam_grant_resource_enm (
    name text primary key
    constraint only_predefined_resource_types_allowed
      check(
        name in (
          '*',
          'alias',
          'auth-method',
          'auth-token',
          'account',
          'billing',
          'controller',
          'credential',
          'credential-library',
          'credential-store',
          'group',
          'host',
          'host-catalog',
          'host-set',
          'managed-group',
          'policy',
          'role',
          'scope',
          'session',
          'session-recording',
          'storage-bucket',
          'target',
          'unknown',
          'user',
          'worker'
        )
      )
  );
  comment on table iam_grant_resource_enm is
    'iam_grant_resource_enm is an enumeration table for resource types.';

  -- wt_canonical_grant domain represents Boundary canonical grant.
  -- A canonical grant is a semicolon-separated list of key=value pairs.
  -- e.g. "ids=*;type=role;actions=read;output_fields=id,name"
  create domain wt_canonical_grant as text
    check(
      value ~ '^(?:[^;=]+=[^;=]+)(?:;[^;=]+=[^;=]+)*?$'
    );
  comment on domain wt_canonical_grant is
    'A canonical grant is a semicolon-separated list of key=value pairs.';

  -- iam_grant is the root table for a grant value object.
  -- A grant can only reference a single resource, including the special
  -- strings "*" to indicate "all" resources, and "unknown" when no resource is set.
  create table iam_grant (
    canonical_grant wt_canonical_grant primary key,
    resource text not null
      constraint iam_grant_resource_enm_fkey
        references iam_grant_resource_enm(name)
        on delete restrict
        on update cascade
  );
  comment on table iam_grant is
    'iam_grant is the root table for a grant value object. A grant can only reference a single resource, including the special strings "*" to indicate "all" resources, and "unknown" when no resource is set.';

  create index iam_grant_resource_ix
    on iam_grant (resource);

commit;