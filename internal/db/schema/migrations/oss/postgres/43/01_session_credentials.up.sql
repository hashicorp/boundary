-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Update table from 23/01_session_credential.up.sql
  alter table session_credential
    drop constraint session_credential_session_id_credential_uq,
    add column credential_sha256 bytea; -- digest(credential, 'sha256')

  -- Migrate existing session_credentials to set an sha256 if there are any
  update session_credential
    set credential_sha256 = digest(credential, 'sha256');

  alter table session_credential
    add constraint session_credential_session_id_credential_sha256_uq
      unique(session_id, credential_sha256);

  -- this trigger is updated in 56/05_mutable_ciphertext_columns.up.sql
  drop trigger immutable_columns on session_credential;
  create trigger immutable_columns before update on session_credential
    for each row execute procedure immutable_columns('session_id', 'credential', 'key_id', 'credential_sha256');
  
  -- session_credentials_sha256_credential sets the credential_sha256
  -- to digest(credential, 'sha256')
  create function session_credentials_sha256_credential() returns trigger
  as $$
  begin
    new.credential_sha256 = digest(new.credential, 'sha256');
    return new;
  end;
  $$ language plpgsql;

  create trigger session_credentials_sha256_credential before insert on session_credential
    for each row execute procedure session_credentials_sha256_credential();

commit;
