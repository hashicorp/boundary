begin;

create table worker_auth_activation_token(
  worker_id wt_public_id primary key
    constraint server_worker_fkey
      references server_worker (public_id)
        on delete cascade
        on update cascade,
  token_id text not null
    constraint token_id_must_not_be_empty
      check(length(trim(token_id)) > 0),
  activation_token_encrypted bytea not null
    constraint activation_token_encrypted_must_not_be_empty
      check(length(activation_token_encrypted) > 0),
  create_time wt_timestamp not null,
  key_id kms_private_id not null
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade,

  constraint worker_auth_activation_token_token_id_uq -- only one valid token at a time for a given worker
    unique(token_id),
  constraint worker_auth_activation_token_activation_token_encrypted_uq
    unique(activation_token_encrypted)
);
comment on table worker_auth_activation_token is
  'worker_auth_activation_token is a table where each row represents an activation token for a worker. Only one activation token is allowed per worker.';

create trigger worker_auth_activation_token_default_create_time_column before insert on worker_auth_activation_token
  for each row execute procedure default_create_time();

create trigger immutable_columns before update on worker_auth_activation_token
  for each row execute procedure immutable_columns('worker_id', 'token_id', 'activation_token_encrypted', 'create_time');

commit;
