-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;


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
      constraint iam_scope_fkey
        references iam_scope(public_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version
  );
  comment on table app_token is
    'app_token is the base table for application tokens that can be scoped to global, org, or project levels.';

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

  -- Function to validate that created_by_user_id exists in iam_user
  create or replace function validate_app_token_created_by_user() returns trigger
  as $$
  begin
    perform 1
      from iam_user 
     where public_id = new.created_by_user_id;
    if not found then
      raise exception 'User ID % does not exist in iam_user', new.created_by_user_id;
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function validate_app_token_created_by_user() is
    'validate_app_token_created_by_user is used to enforce that created_by_user_id exists in iam_user table';

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

  create table app_token_permission (
    private_id wt_private_id primary key,
    app_token_id wt_public_id not null,
      constraint app_token_permission_app_token_id_idx
        foreign key (app_token_id) references app_token(public_id)
        on delete cascade
        on update cascade
  );
  comment on table app_token_permission is
    'app_token_permission is the base table for application token permissions.';

  -- Create index on app_token_id for efficient token-based lookups
  create index app_token_permission_app_token_id_idx on app_token_permission (app_token_id);

  create function insert_app_token_permission_subtype() returns trigger
  as $$
  begin
    insert into app_token_permission
      (private_id, app_token_id)
    values
      (new.private_id, new.app_token_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_app_token_permission_subtype() is
    'insert_app_token_permission_subtype is used to automatically insert a row into the app_token_permission table '
    'whenever a row is inserted into the subtype table';


  create table app_token_permission_grant (
    permission_id wt_private_id
      constraint app_token_permission_grant_fkey
      references app_token_permission(private_id)
        on delete cascade
        on update cascade,
    canonical_grant wt_canonical_grant not null
      constraint app_token_permission_iam_grant_fkey
        references iam_grant(canonical_grant)
        on delete cascade
        on update cascade,
    raw_grant text not null
      constraint raw_grant_must_not_be_empty
      check(
        length(trim(raw_grant)) > 0
      ),
    primary key(permission_id, canonical_grant)
  );
  comment on table app_token_permission_grant is
    'app_token_permission_grant contains grants assigned to app tokens in project scope';

  create trigger upsert_canonical_grant_trigger before insert on app_token_permission_grant
    for each row execute procedure upsert_canonical_grant();


  -- Add oplog entries for tracking changes (similar to IAM role tables)
  insert into oplog_ticket (name, version)
  values 
    ('app_token', 1),
    ('app_token_global', 1),
    ('app_token_org', 1),
    ('app_token_project', 1);

commit;