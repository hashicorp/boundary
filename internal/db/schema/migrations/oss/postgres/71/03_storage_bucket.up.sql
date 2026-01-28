-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table plugin_storage_supported (
  public_id wt_plugin_id primary key
    references plugin(public_id)
    on delete cascade
    on update cascade
  );
  comment on table plugin_storage_supported is
    'plugin_storage_supported entries indicate that a given plugin is flagged as a storage plugin.';

  -- flag aws plugin as supporting storage
  insert into plugin_storage_supported
  (public_id)
  select public_id
  from plugin
  where name = 'aws';

  create table storage_plugin_storage_bucket (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
      references iam_scope(public_id)
      on delete restrict
      on update cascade,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    plugin_id wt_public_id not null
      constraint plugin_storage_supported_fkey
      references plugin_storage_supported(public_id)
      on delete cascade
      on update cascade,
    bucket_name text not null
      constraint bucket_name_must_not_be_empty
      check(length(trim(bucket_name)) > 0),
    bucket_prefix text,
    worker_filter wt_bexprfilter not null,
    attributes bytea,
    secrets_hmac bytea not null
      constraint secrets_hmac_must_not_be_empty
      check(length(secrets_hmac) > 0),
    constraint storage_plugin_storage_bucket_scope_id_name_uq
    unique(scope_id, name)
  );
  comment on table storage_plugin_storage_bucket is
    'storage_plugin_storage_bucket entries refer to a specific storage bucket that a storage plugin uses for all external storage.';

  create trigger update_time_column before update on storage_plugin_storage_bucket
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on storage_plugin_storage_bucket
    for each row execute procedure default_create_time();

  create trigger update_version_column after update on storage_plugin_storage_bucket
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on storage_plugin_storage_bucket
    for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time', 'bucket_name');

  -- storage_bucket_scope_id_valid() is a trigger function for
  -- subtypes of storage_bucket
  create or replace function storage_bucket_scope_id_valid() returns trigger
  as $$
  begin

    perform from iam_scope where public_id = new.scope_id and type in ('global', 'org');
    if not found then
      raise exception 'invalid scope type for storage bucket creation';
    end if;
    return new;

  end;
  $$ language plpgsql;
  comment on function storage_bucket_scope_id_valid is
    'storage_bucket_scope_id_valid is a trigger function for subtypes of storage_bucket that checks if the scope_id being inserted is a global or org level scope.';

  create trigger storage_bucket_scope_id_valid before insert on storage_plugin_storage_bucket
    for each row execute procedure storage_bucket_scope_id_valid();

  -- allow operations on storage bucket to be oplogged
  insert into oplog_ticket
    (name, version)
  values
    ('storage_plugin_storage_bucket', 1);

  create table storage_plugin_storage_bucket_secret (
    storage_bucket_id wt_public_id primary key
      references storage_plugin_storage_bucket(public_id)
      on delete cascade
      on update cascade,
    secrets_encrypted bytea not null
      constraint secrets_must_not_be_empty
      check(length(secrets_encrypted) > 0),
    key_id text not null
      constraint kms_data_key_version_fkey
      references kms_data_key_version(private_id)
      on delete restrict
      on update cascade
  );
  comment on table storage_plugin_storage_bucket is
    'storage_plugin_storage_bucket_secret are the secrets used to access and update a storage bucket by a plugin.';

  create view storage_plugin_storage_bucket_with_secret as
  select
    spsb.public_id,
    spsb.scope_id,
    spsb.name,
    spsb.description,
    spsb.create_time,
    spsb.update_time,
    spsb.version,
    spsb.plugin_id,
    spsb.bucket_name,
    spsb.bucket_prefix,
    spsb.worker_filter,
    spsb.attributes,
    spsb.secrets_hmac,
    spsbs.secrets_encrypted,
    spsbs.key_id
  from storage_plugin_storage_bucket spsb
  left join storage_plugin_storage_bucket_secret spsbs
    on spsbs.storage_bucket_id = spsb.public_id;
  comment on view storage_plugin_storage_bucket_with_secret is
    'storage bucket with its associated encrypted secrets';

commit;
