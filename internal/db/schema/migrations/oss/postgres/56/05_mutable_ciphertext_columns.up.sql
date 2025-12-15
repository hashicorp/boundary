-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- We need to make private_key and key_id mutable, so that we can rewrap them.
  drop trigger immutable_columns on worker_auth_ca_certificate;

  create trigger immutable_columns before update on worker_auth_ca_certificate
    for each row execute procedure immutable_columns('serial_number', 'certificate', 'not_valid_before', 'not_valid_after', 'public_key', 'state', 'issuing_ca');


  -- We need to make token mutable so that we can rewrap it.
  drop trigger immutable_auth_token_columns on auth_token;
  drop function immutable_auth_token_columns;


  -- We need to make token and token_hmac mutable, so that we can rewrap them.
  drop trigger immutable_columns on credential_vault_token;

  create trigger immutable_columns before update on credential_vault_token
    for each row execute procedure immutable_columns('store_id','create_time');


  -- And again on credential and key_id (and the hash of credential).
  drop trigger immutable_columns on session_credential;

  create trigger immutable_columns before update on session_credential
    for each row execute procedure immutable_columns('session_id');


  -- And one final time on worker auth for controller priv key and key id.
  drop trigger immutable_columns on worker_auth_authorized;

  create trigger immutable_columns before update on worker_auth_authorized
    for each row execute function immutable_columns('worker_key_identifier', 'worker_id', 'worker_signing_pub_key', 'worker_encryption_pub_key', 'nonce', 'create_time');


  drop trigger immutable_columns on worker_auth_server_led_activation_token;

  create trigger immutable_columns before update on worker_auth_server_led_activation_token
    for each row execute procedure immutable_columns('worker_id', 'token_id');

commit;
