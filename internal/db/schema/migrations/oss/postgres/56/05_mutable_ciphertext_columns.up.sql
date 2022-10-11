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

commit;
