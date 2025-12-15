-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table worker_auth_server_led_activation_token(
  worker_id wt_public_id primary key
    constraint server_worker_fkey
      references server_worker (public_id)
        on delete cascade
        on update cascade,
  token_id text not null
    constraint token_id_must_not_be_empty
      check(length(trim(token_id)) > 0),
  creation_time_encrypted bytea not null
    constraint creation_time_encrypted_must_not_be_empty
      check(length(creation_time_encrypted) > 0),
  key_id kms_private_id not null
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade,

  constraint worker_auth_server_led_activation_token_token_id_uq -- only one valid token at a time for a given worker
    unique(token_id)
);
comment on table worker_auth_server_led_activation_token is
  'worker_auth_server_led_activation_token is a table where each row represents an activation token for a worker. Only one activation token is allowed per worker.';

-- this trigger is updated in 56/05_mutable_ciphertext_columns.up.sql
create trigger immutable_columns before update on worker_auth_server_led_activation_token
  for each row execute procedure immutable_columns('worker_id', 'token_id', 'creation_time_encrypted');

commit;
