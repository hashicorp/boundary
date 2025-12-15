-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table worker_storage_bucket_credential_permission_type_enm (
    type text primary key
      constraint only_predefined_permission_types_allowed
      check (
        type in (
          'read',
          'write',
          'delete'
        )
      )
  );
  comment on table worker_storage_bucket_credential_permission_type_enm is
    'worker_storage_bucket_credential_permission_type_enm is an enumeration table for storage bucket credential permission types.';

  insert into worker_storage_bucket_credential_permission_type_enm (type)
  values
    ('read'),
    ('write'),
    ('delete');

  create table worker_storage_bucket_credential_state_enm (
    state text primary key
      constraint only_predefined_state_types_allowed
      check (
        state in (
          'ok',
          'error',
          'unknown'
        )
      )
  );
  comment on table worker_storage_bucket_credential_state_enm is
    'worker_storage_bucket_credential_state_enm is an enumeration table for storage bucket credential state types.';

  insert into worker_storage_bucket_credential_state_enm (state)
  values
    ('ok'),
    ('error'),
    ('unknown');

  create table worker_storage_bucket_credential_state (
    worker_id wt_public_id
      constraint server_worker_fkey
        references server_worker(public_id)
        on delete cascade
        on update cascade,
    storage_bucket_credential_id wt_private_id
      constraint storage_bucket_credential_id_fkey
        references storage_bucket_credential(private_id)
        on delete cascade
        on update cascade,
    permission_type text not null
      constraint worker_storage_bucket_credential_permission_type_enm_fkey
        references worker_storage_bucket_credential_permission_type_enm(type)
        on delete restrict
        on update cascade,
    state text not null
      constraint worker_storage_bucket_credential_state_enm_fkey
        references worker_storage_bucket_credential_state_enm(state)
        on delete restrict
        on update cascade,
    error_details text,
    checked_at wt_timestamp,
    primary key (worker_id, storage_bucket_credential_id, permission_type)
  );
  comment on table worker_storage_bucket_credential_state is
    'worker storage bucket credential state contains entries that represent an association between a worker and storage bucket credential.';

  create trigger immutable_columns before update on worker_storage_bucket_credential_state
    for each row execute procedure immutable_columns('worker_id', 'storage_bucket_credential_id');

commit;
