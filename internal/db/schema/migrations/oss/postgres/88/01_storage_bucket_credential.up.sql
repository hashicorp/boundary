-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table storage_bucket_credential (
    private_id wt_private_id primary key,
    storage_bucket_id wt_public_id not null
    constraint storage_plugin_storage_bucket_fkey
      references storage_plugin_storage_bucket(public_id)
      on delete cascade
      on update cascade
      deferrable initially deferred
    constraint storage_bucket_credential_storage_bucket_id_uq
      unique
  );
  comment on table storage_bucket_credential is
    'storage bucket credential contains entries that represent an abstract storage bucket credential.';

  create trigger immutable_columns before update on storage_bucket_credential
    for each row execute procedure immutable_columns('private_id', 'storage_bucket_id');

  create table storage_bucket_credential_managed_secret (
    private_id wt_private_id primary key default wt_url_safe_id()
    constraint storage_bucket_credential_fkey
      references storage_bucket_credential(private_id)
      on delete cascade
      on update cascade,
    storage_bucket_id wt_public_id not null,
    secrets_encrypted bytea not null
    constraint secrets_must_not_be_empty
      check(length(secrets_encrypted) > 0),
    key_id wt_public_id not null
    constraint kms_data_key_version_fkey
      references kms_data_key_version(private_id)
      on delete cascade
      on update cascade
  );
  comment on table storage_bucket_credential_managed_secret is
    'storage bucket credential managed secret contains entries that represent an storage bucket credential subtype.';

  create trigger immutable_columns before update on storage_bucket_credential_managed_secret
    for each row execute procedure immutable_columns('private_id', 'storage_bucket_id');

  create table storage_bucket_credential_environmental (
    private_id wt_private_id primary key default wt_url_safe_id()
    constraint storage_bucket_credential_fkey
      references storage_bucket_credential(private_id)
      on delete cascade
      on update cascade,
    storage_bucket_id wt_public_id not null
  );
  comment on table storage_bucket_credential_environmental is
    'storage bucket credential environmental contains entries that represent an storage bucket credential subtype.';

  create trigger immutable_columns before update on storage_bucket_credential_environmental
    for each row execute procedure immutable_columns('private_id', 'storage_bucket_id');

  create function insert_storage_bucket_credential_subtype() returns trigger
  as $$
  begin
    insert into storage_bucket_credential
      (private_id, storage_bucket_id)
    values
      (new.private_id, new.storage_bucket_id);
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_storage_bucket_credential_subtype before insert on storage_bucket_credential_environmental
    for each row execute procedure insert_storage_bucket_credential_subtype();

  create trigger insert_storage_bucket_credential_subtype before insert on storage_bucket_credential_managed_secret
    for each row execute procedure insert_storage_bucket_credential_subtype();

  create function delete_storage_bucket_credential_subtype() returns trigger
  as $$
  begin
    delete from storage_bucket_credential
    where private_id = old.private_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  create trigger delete_storage_bucket_credential_subtype after delete on storage_bucket_credential_environmental
    for each row execute procedure delete_storage_bucket_credential_subtype();

  create trigger delete_storage_bucket_credential_subtype after delete on storage_bucket_credential_managed_secret
    for each row execute procedure delete_storage_bucket_credential_subtype();

  -- migrate secrets from storage_plugin_storage_bucket_secret to storage_bucket_credential_managed_secret
  insert into storage_bucket_credential_managed_secret
    (storage_bucket_id, secrets_encrypted, key_id)
  select storage_bucket_id, secrets_encrypted, key_id
    from storage_plugin_storage_bucket_secret;

  -- create storage_bucket_credential_environmental when storage_plugin_storage_bucket_secret does not exist
  insert into storage_bucket_credential_environmental
    (storage_bucket_id)
  select storage_bucket.public_id
    from (
      select public_id
        from storage_plugin_storage_bucket
       where public_id not in (select storage_bucket_id from storage_plugin_storage_bucket_secret)
    ) storage_bucket;

  -- temporarily set the new storage_bucket_credential_id column to a text type
  -- so that we can update the value later 
  alter table storage_plugin_storage_bucket
    add column storage_bucket_credential_id text
  ;

  -- set storage_bucket_credential_id to the expected value
  update storage_plugin_storage_bucket
    set (storage_bucket_credential_id) = (
      select private_id
        from storage_bucket_credential
       where storage_plugin_storage_bucket.public_id = storage_bucket_credential.storage_bucket_id
  );

  -- update storage_bucket_credential_id column to the expected wt_private_id type
  alter table storage_plugin_storage_bucket
    alter column storage_bucket_credential_id type wt_private_id
  ;

  -- enforce foreign key reference constaint for storage_bucket_credential_id column
  alter table storage_plugin_storage_bucket
    add constraint storage_bucket_credential_id_fkey
      foreign key (storage_bucket_credential_id)
      references storage_bucket_credential(private_id)
      on update cascade
      deferrable initially deferred
  ;

  -- Replaces view from 75/01_storage_bucket.up.sql
  drop view storage_plugin_storage_bucket_with_secret;
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
    sbcms.secrets_encrypted,
    sbcms.key_id,
    spsb.storage_bucket_credential_id
  from storage_plugin_storage_bucket spsb
  left join storage_bucket_credential_managed_secret sbcms
    on sbcms.storage_bucket_id = spsb.public_id;
  comment on view storage_plugin_storage_bucket_with_secret is
    'storage_plugin_storage_bucket_with_secret is a view where each row contains a storage bucket. '
    'Encrypted secret and hmac value is not returned if a secret is not associated with the storage bucket.';

  -- Replaces view from 82/04_find_session_recordings_for_delete.up.sql
  drop view find_session_recordings_for_delete;
  create view find_session_recordings_for_delete as
    select
      -- fields for session recordings
      rs.public_id,
      rs.storage_bucket_id,

      -- fields for storage buckets. note this is ALL storage bucket fields
      sb.scope_id    as storage_bucket_scope_id,
      sb.name        as storage_bucket_name,
      sb.description as storage_bucket_description,
      sb.create_time as storage_bucket_create_time,
      sb.update_time as storage_bucket_update_time,
      sb.version     as storage_bucket_version,
      sb.plugin_id,
      sb.bucket_name,
      sb.bucket_prefix,
      sb.worker_filter,
      sb.attributes,
      sb.secrets_hmac,
      sb.storage_bucket_credential_id,

      -- fields for storage bucket secrets
      sbcms.secrets_encrypted,
      sbcms.key_id,

      -- fields for storage bucket plugins
      plg.scope_id    as plugin_scope_id,
      plg.name        as plugin_name,
      plg.description as plugin_description

    from recording_session rs
      left join storage_plugin_storage_bucket sb
        on sb.public_id = rs.storage_bucket_id
      left join storage_bucket_credential_managed_secret sbcms
        on sbcms.storage_bucket_id = sb.public_id
      left join plugin plg
        on plg.public_id = sb.plugin_id
    where rs.delete_after < now() or rs.delete_time < now()
    order by rs.delete_time desc, rs.delete_after desc;
  comment on view find_session_recordings_for_delete is
    'find_session_recordings_for_delete is used by the delete_session_recording job to find all '
    'session recordings that need to be automatically deleted along with their storage buckets.';

  -- Drops table from 71/03_storage_bucket.up.sql
  drop table storage_plugin_storage_bucket_secret;
  
  create view storage_bucket_credential_all_subtypes as
  select
    private_id,
    storage_bucket_id,
    key_id,
    secrets_encrypted,
    'managed_secret' as type
  from
    storage_bucket_credential_managed_secret
  union  
  select
    private_id,
    storage_bucket_id,
    '' as key_id, -- key_id is not applicable to environmental subtype
    ''::bytea as secrets_encrypted, -- secrets_encrypted is not applicable to environmental subtype
    'environmental' as type
  from 
    storage_bucket_credential_environmental;
  comment on view storage_bucket_credential_all_subtypes is
    'storage_bucket_credential_all_subtypes is a view that contains all storage bucket credential '
    'subtypes. There are two subtypes: environmental & managed secret. Columns that are not applicable '
    'to the given subtype will have an empty value by default, not null.';

commit;
