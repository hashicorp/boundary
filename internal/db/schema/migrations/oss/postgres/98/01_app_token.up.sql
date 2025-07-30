-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;


  -- Create the enumeration table for app token status
  create table app_token_status_enm (
    name text primary key
      constraint only_predefined_app_token_status_allowed
        check(
          name in (
            'active',
            'revoked',
            'expired'
          )
        )
  );
  comment on table app_token_status_enm is
    'app_token_status_enm is an enumeration table for app token status types.';

  -- Insert the predefined app token statuses
  insert into app_token_status_enm (name)
  values
    ('active'),
    ('revoked'),
    ('expired');

  -- Create the enumeration table for app token global grant scope
  create table app_token_global_grant_scope_enm (
    name text primary key
      constraint only_predefined_app_token_global_grant_scope_allowed
        check(
          name in (
            'individual',
            'children',
            'descendants'
          )
        )
  );
  comment on table app_token_global_grant_scope_enm is
    'app_token_global_grant_scope_enm is an enumeration table for app token global grant scope types.';

  -- Insert the predefined app token global grant scopes
  insert into app_token_global_grant_scope_enm (name)
  values
    ('individual'),
    ('children'),
    ('descendants');

  -- Create the enumeration table for app token org grant scope
  create table app_token_org_grant_scope_enm (
    name text primary key
      constraint only_predefined_app_token_org_grant_scope_allowed
        check(
          name in (
            'individual',
            'children'
          )
        )
  );
  comment on table app_token_org_grant_scope_enm is
    'app_token_org_grant_scope_enm is an enumeration table for app token org grant scope types.';

  -- Insert the predefined app token org grant scopes
  insert into app_token_org_grant_scope_enm (name)
  values
    ('individual'),
    ('children');

  -- Main app_token table similar to iam_role structure
  create table app_token (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_scope_id_fkey
        references iam_scope(public_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    status text not null default 'active'
      constraint app_token_status_enm_fkey
        references app_token_status_enm(name)
        on delete restrict
        on update cascade,
    created_time wt_timestamp,
    updated_time wt_timestamp,
    created_by wt_user_id not null
      constraint app_token_created_by_fkey
        references iam_user_hst(history_id)
        on delete restrict
        on update cascade,
    approximate_last_access_time wt_timestamp
      constraint last_access_time_must_not_be_after_expiration_time
      check(
        approximate_last_access_time <= expiration_time
      ),
    usage_expiry_seconds integer not null default 0
      constraint usage_expiry_seconds_must_be_non_negative
        check(usage_expiry_seconds >= 0),
    expiration_time wt_timestamp
      constraint created_time_must_not_be_after_expiration_time
      check(
        created_time <= expiration_time
      ),
    key_id text not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade,
    token bytea not null unique,
    version wt_version,
    constraint name_scope_id_uq
      unique(name, scope_id)
  );
  comment on table app_token is
    'app_token is the main table for application tokens that can be scoped to global, org, or project levels.';

  -- Add triggers for app_token
  create trigger default_create_time_column before insert on app_token
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token
    for each row execute procedure update_time_column();

  create trigger update_version_column before update on app_token
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on app_token
    for each row execute procedure immutable_columns('public_id', 'created_time', 'scope_id');

  -- App token deleted tracking table
  create table app_token_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table app_token_deleted is
    'app_token_deleted holds the ID and delete_time of every deleted app token. '
    'It is automatically trimmed of records older than 30 days by a job.';

  -- Create trigger for app_token deletion tracking
  create trigger insert_deleted_id after delete on app_token
    for each row execute function insert_deleted_id('app_token_deleted');

  -- Create index on delete_time for app_token_deleted
  create index app_token_deleted_delete_time_idx on app_token_deleted (delete_time);

  -- App token permissions table
  create table app_token_permission (
    public_id wt_public_id primary key,
    app_token_id wt_public_id not null
      references app_token(public_id)
      on delete cascade
      on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_scope_id_fkey
        references iam_scope(public_id)
        on delete cascade
        on update cascade,
    created_time wt_timestamp
  );
  comment on table app_token_permission is
    'app_token_permission contains permissions associated with app tokens.';

  -- Add triggers for app_token_permission
  create trigger default_create_time_column before insert on app_token_permission
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permission
    for each row execute procedure immutable_columns('created_time', 'app_token_id', 'scope_id');

  create table app_token_permissions_resource_grant (
    canonical_grant wt_canonical_grant primary key,
    resource text not null
      constraint iam_grant_resource_enm_fkey
        references iam_grant_resource_enm(name)
        on delete restrict
        on update cascade
  );
  comment on table app_token_permissions_resource_grant is
    'app_token_permissions_resource_grant contains resource-specific grants for app token permissions.';

  create index app_token_permissions_resource_grant_ix
    on app_token_permissions_resource_grant (resource);

  create table app_token_permissions_grant (
    app_token_permission_id wt_public_id
      references app_token_permission(public_id)
      on delete cascade
      on update cascade,
    canonical_grant wt_canonical_grant not null
      constraint app_token_permissions_resource_grant_fkey
        references app_token_permissions_resource_grant(canonical_grant)
        on delete cascade
        on update cascade,
    raw_grant text not null
      constraint raw_grant_must_not_be_empty
      check(
        length(trim(raw_grant)) > 0
      ),
    primary key(app_token_permission_id, canonical_grant)
  );
  comment on table app_token_permissions_grant is
    'app_token_permissions_grant contains grants assigned to app tokens.';


  -- App token permissions global table
  create table app_token_permissions_global (
    public_id wt_public_id primary key
      constraint app_token_permission_fkey
        references app_token_permission(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_global_fkey
        references iam_scope_global(scope_id)
        on delete cascade
        on update cascade,
    label text,
    grant_this_role_scope boolean not null default false,
    grant_scope text not null
      constraint app_token_global_grant_scope_enm_fkey
        references app_token_global_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    created_time wt_timestamp,
    constraint app_token_permissions_global_grant_scope_public_id_uq
      unique(grant_scope, public_id)
  );
  comment on table app_token_permissions_global is
    'app_token_permissions_global contains global scope-specific permissions for app tokens.';

  -- Add triggers for app_token_permissions_global
  create trigger default_create_time_column before insert on app_token_permissions_global
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permissions_global
    for each row execute procedure immutable_columns('public_id', 'scope_id', 'label', 'grant_scope', 'grant_this_role_scope', 'created_time');

  create table app_token_permissions_global_individual_org_grant_scope (
    app_token_permission_id wt_public_id
      constraint app_token_permissions_global_fkey
        references app_token_permissions_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the app_token_permissions_global
    -- grant_scope, it ensures that app_token_permissions_global is set to 'individual'
    -- if this table is populated for the corresponding permission.
    grant_scope text not null
       constraint only_individual_grant_scope_allowed
         check(
          grant_scope = 'individual'
        ), 
    constraint app_token_permissions_global_grant_scope_fkey
      foreign key (app_token_permission_id, grant_scope)
      references app_token_permissions_global(public_id, grant_scope)
      on delete cascade
      on update cascade,
    created_time wt_timestamp,
    primary key(app_token_permission_id, scope_id)
  );
  comment on table app_token_permissions_global_individual_org_grant_scope is
    'app_token_permissions_global_individual_org_grant_scope is a list of individually granted org scope to global app token permissions with grant_scope of individual.';

  -- Add trigger for app_token_permissions_global_individual_org_grant_scope
  create trigger default_create_time_column before insert on app_token_permissions_global_individual_org_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permissions_global_individual_org_grant_scope
    for each row execute procedure immutable_columns('app_token_permission_id', 'scope_id', 'grant_scope', 'created_time');

  create table app_token_permissions_global_individual_project_grant_scope (
    app_token_permission_id wt_public_id
      constraint app_token_permissions_global_fkey
        references app_token_permissions_global(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the app_token_permissions_global
    -- grant_scope, it ensures that app_token_permissions_global is set to 'individual'
    -- if this table is populated for the corresponding permission.
    -- both children and individual are allowed for this global permission
    -- because projects can be individually in addition to children 
    -- which grants all orgs
    grant_scope text not null
       constraint only_individual_grant_scope_allowed
         check(
          grant_scope in ('individual')
        ),
    constraint app_token_permissions_global_grant_scope_fkey
      foreign key (app_token_permission_id, grant_scope)
      references app_token_permissions_global(public_id, grant_scope)
      on delete cascade
      on update cascade,
    created_time wt_timestamp,
    primary key(app_token_permission_id, scope_id)
  );
  comment on table app_token_permissions_global_individual_project_grant_scope is
    'app_token_permissions_global_individual_project_grant_scope is a list of individually granted project scope table to global app token permissions with grant_scope of individual or children.';

  -- Add trigger for app_token_permissions_global_individual_project_grant_scope
  create trigger default_create_time_column before insert on app_token_permissions_global_individual_project_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permissions_global_individual_project_grant_scope
    for each row execute procedure immutable_columns('app_token_permission_id', 'scope_id', 'grant_scope', 'created_time');

  -- App token permissions org table
  create table app_token_permissions_org (
    public_id wt_public_id primary key
      constraint app_token_permission_fkey
        references app_token_permission(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_org_fkey
        references iam_scope_org(scope_id)
        on delete cascade
        on update cascade,
    label text,
    grant_this_role_scope boolean not null default false,
    grant_scope text not null
      constraint app_token_org_grant_scope_enm_fkey
        references app_token_org_grant_scope_enm(name)
        on delete restrict
        on update cascade,
    version wt_version,
    created_time wt_timestamp,
    constraint app_token_permissions_org_grant_scope_public_id_uq
      unique(grant_scope, public_id)
  );
  comment on table app_token_permissions_org is
    'app_token_permissions_org is a subtype table of the app_token_permission table. It is used to store permissions that are scoped to an org.';

  -- Add triggers for app_token_permissions_org
  create trigger default_create_time_column before insert on app_token_permissions_org
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on app_token_permissions_org
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on app_token_permissions_org
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on app_token_permissions_org
    for each row execute procedure immutable_columns('public_id', 'scope_id', 'label', 'grant_this_role_scope', 'grant_scope', 'version', 'created_time');

  create table app_token_permissions_org_individual_grant_scope (
    app_token_permission_id wt_public_id
      constraint app_token_permissions_org_fkey
        references app_token_permissions_org(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    -- grant_scope is used for constraint checking.
    -- This restricts the grant_scope to be 'individual'
    -- and since it is also a foreign key to the app_token_permissions_org
    -- grant_scope, it ensures that app_token_permissions_org is set to 'individual'
    -- if this table is populated for the corresponding permission.
    grant_scope text not null
      constraint only_individual_grant_scope_allowed
        check(
            grant_scope = 'individual'
        ),
    constraint app_token_permissions_org_grant_scope_fkey
      foreign key (app_token_permission_id, grant_scope)
      references app_token_permissions_org(public_id, grant_scope)
        on delete cascade
        on update cascade,
    created_time wt_timestamp,
    primary key(app_token_permission_id, scope_id)
  );
  comment on table app_token_permissions_org_individual_grant_scope is
    'app_token_permissions_org_individual_grant_scope is a list of individually granted project scope to org app token permissions with grant_scope of individual';

  -- Add trigger for app_token_permissions_org_individual_grant_scope
  create trigger default_create_time_column before insert on app_token_permissions_org_individual_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permissions_org_individual_grant_scope
    for each row execute procedure immutable_columns('app_token_permission_id', 'scope_id', 'grant_scope', 'created_time');

  -- App token permissions project table
  create table app_token_permissions_project (
    public_id wt_public_id primary key
      constraint app_token_permission_fkey
        references app_token_permission(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    label text,
    grant_this_role_scope boolean not null default false,
    created_time wt_timestamp,
    constraint app_token_permissions_project_label_scope_id_uq
        unique(label, scope_id)
  );
  comment on table app_token_permissions_project is
    'app_token_permissions_project is a subtype table of the app_token_permission table. It is used to store permissions that are scoped to a project.';

  -- Add triggers for app_token_permissions_project
  create trigger default_create_time_column before insert on app_token_permissions_project
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on app_token_permissions_project
    for each row execute procedure immutable_columns('scope_id', 'label', 'grant_this_role_scope', 'created_time');




  -- Add oplog entries for tracking changes (similar to IAM role tables)
  insert into oplog_ticket (name, version)
  values 
    ('app_token', 1),
    ('app_token_global', 1),
    ('app_token_org', 1),
    ('app_token_project', 1);
commit;