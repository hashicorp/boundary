begin;

create table worker_auth_activation_token(
  token_id text not null primary key,
  worker_id wt_public_id
    constraint server_worker_fkey
      references server_worker (public_id)
        on delete cascade
        on update cascade,
  activation_token_encrypted bytea not null,
  create_time wt_timestamp,
  key_id text not null
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade,

  constraint worker_auth_activation_token_worker_id_uq -- only one valid token at a time for a given worker
    unique(worker_id),
  constraint worker_auth_activation_token_activation_token_encrypted_uq
    unique(activation_token_encrypted)
);
comment on table worker_auth_activation_token is
  'worker_auth_activation_token is a table where each row represents an activation token for a worker. Only one activation token is allowed per worker.';

create trigger worker_auth_activation_token_default_create_time_column before insert on worker_auth_activation_token
  for each row execute procedure default_create_time();

create trigger immutable_columns before update on worker_auth_activation_token
  for each row execute procedure immutable_columns('token_id', 'worker_id', 'activation_token_encrypted', 'create_time');

commit;
