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
    approximate_last_access_time wt_timestamp,
    expiration_time wt_timestamp,
    time_to_stale_seconds integer not null default 0
      constraint time_to_stale_seconds_must_be_non_negative
        check(time_to_stale_seconds >= 0)
  );
  comment on table app_token is
    'app_token is the base table for application tokens that can be scoped to global, org, or project levels.';

  create trigger immutable_columns before update on app_token
    for each row execute procedure immutable_columns('public_id', 'create_time', 'scope_id', 'expiration_time', 'time_to_stale_seconds');

  create function insert_app_token_subtype() returns trigger
  as $$
  begin
    insert into app_token
      (public_id, scope_id, expiration_time, time_to_stale_seconds)
    values
      (new.public_id, new.scope_id, new.expiration_time, new.time_to_stale_seconds);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_app_token_subtype() is
    'insert_app_token_subtype is used to automatically insert a row into the app_token table '
    'whenever a row is inserted into the subtype table';

-- Add trigger to update the new update_time column on every app_token subtype update.
  create function update_app_token_table_update_time() returns trigger
  as $$
  begin
    update app_token 
       set update_time = new.update_time 
     where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_app_token_table_update_time() is
    'update_app_token_table_update_time is used to automatically update the update_time '
      'of the base table whenever one of the subtype app_token tables are updated';

-- Add trigger to update the new approximate_last_access_time column on every app_token subtype update.
  create function update_app_token_table_approximate_last_access_time() returns trigger
  as $$
  begin
    -- Only update if approximate_last_access_time has actually changed
    if old.approximate_last_access_time is distinct from new.approximate_last_access_time then
      update app_token 
         set approximate_last_access_time = new.approximate_last_access_time 
       where public_id = new.public_id;
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_app_token_table_approximate_last_access_time() is
    'update_app_token_table_approximate_last_access_time is used to automatically update the approximate_last_access_time '
      'of the base table whenever one of the subtype app_token tables are updated';

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

  -- Function to validate that revoked can only be updated from false to true
  create or replace function validate_app_token_revocation() returns trigger
  as $$
  begin
    -- For updates, check revoked field changes
    if old.revoked is distinct from new.revoked then
      -- Only allow change from false to true
      if not (old.revoked = false and new.revoked = true) then
        raise exception 'App token cannot be unrevoked. revoked value. Current: %, Attempted: %', 
          old.revoked, new.revoked;
      end if;
    end if;
    
    return new;
  end;
  $$ language plpgsql;
  comment on function validate_app_token_revocation() is
    'validate_app_token_revocation ensures that the revoked field can only be updated from false to true, '
    'preventing tokens from being un-revoked or other invalid state transitions';

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


  create table app_token_cipher (
    app_token_id wt_public_id primary key
      constraint app_token_cipher_app_token_fkey
        references app_token(public_id)
          on delete cascade
          on update cascade,
    key_id text not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade,
    token bytea not null unique
  );
  comment on table app_token_cipher is
    'app_token_cipher is the table for application token encryption keys. '
    'This was split out from the app_token table to avoid re-encrypting tokens when tokens are no longer valid. '
    'When an app token becomes invalid, the associated row in this table may be deleted.';

  -- Add oplog entries for tracking changes (similar to IAM role tables)
  insert into oplog_ticket (name, version)
  values 
    ('app_token', 1),
    ('app_token_global', 1),
    ('app_token_org', 1),
    ('app_token_project', 1);

commit;