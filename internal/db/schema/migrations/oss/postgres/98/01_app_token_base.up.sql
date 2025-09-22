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


  create table app_token (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_global_scope_id_fkey
        references iam_scope_global(scope_id)
        on delete cascade
        on update cascade,
    created_time wt_timestamp,
    updated_time wt_timestamp,
    version wt_version
  );
  comment on table app_token is
    'app_token is the base table for application tokens that can be scoped to global, org, or project levels.';

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


  create table app_token_permission_resource_grant (
    canonical_grant wt_canonical_grant primary key,
    resource text not null
      constraint iam_grant_resource_enm_fkey
        references iam_grant_resource_enm(name)
        on delete restrict
        on update cascade
  );
  comment on table app_token_permission_resource_grant is
    'app_token_permission_resource_grant contains resource-specific grants for app token permissions.';

  create index app_token_permission_resource_grant_ix
    on app_token_permission_resource_grant (resource);

  -- Add oplog entries for tracking changes (similar to IAM role tables)
  insert into oplog_ticket (name, version)
  values 
    ('app_token', 1),
    ('app_token_global', 1),
    ('app_token_org', 1),
    ('app_token_project', 1);



  create function insert_app_token_subtype() returns trigger
  as $$
  begin
    insert into app_token
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_app_token_subtype() is
    'insert_app_token_subtype is used to automatically insert a row into the app_token table '
    'whenever a row is inserted into the subtype table';


commit;