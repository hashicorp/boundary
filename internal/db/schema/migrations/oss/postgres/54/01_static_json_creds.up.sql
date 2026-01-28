-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table credential_static_json_credential (
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint credential_static_store_fkey
        references credential_static_store (public_id)
        on delete cascade
        on update cascade,
    project_id wt_public_id not null,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,

    object_encrypted bytea not null
      constraint object_encrypted_must_not_be_empty
        check(length(object_encrypted) > 0),
    object_hmac bytea not null
      constraint object_hmac_must_not_be_empty
        check(length(object_hmac) > 0),
    key_id kms_private_id not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade,
    constraint credential_static_fkey
      foreign key (project_id, store_id, public_id)
        references credential_static (project_id, store_id, public_id)
        on delete cascade
        on update cascade,
    constraint credential_static_json_credential_store_id_name_uq
      unique(store_id, name),
    constraint credential_static_json_credential_store_id_public_id_uq
      unique(store_id, public_id)
  );
  comment on table credential_static_json_credential is
    'credential_static_json_credential is a table where each row is a resource that represents a static json credential. '
    'It is a credential_static subtype and an aggregate root.';

  create trigger update_version_column after update on credential_static_json_credential
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_static_json_credential
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_static_json_credential
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_static_json_credential
    for each row execute procedure immutable_columns('public_id', 'store_id', 'project_id', 'create_time');

  create trigger insert_credential_static_subtype before insert on credential_static_json_credential
    for each row execute procedure insert_credential_static_subtype();

  create trigger delete_credential_static_subtype after delete on credential_static_json_credential
    for each row execute procedure delete_credential_static_subtype();

  insert into oplog_ticket (name, version)
    values
      ('credential_static_json_credential', 1);

commit;
