begin;

  -- Update table from 23/01_session_credential.up.sql
  alter table session_credential
    drop constraint session_credential_session_id_credential_uq,
    add column credential_hmac bytea; -- digest(credential, 'sha256')

  -- Migrate existing session_credentials to set an hmac if there are any
  update session_credential
    set credential_hmac = digest(credential, 'sha256');

  alter table session_credential
    add constraint session_credential_session_id_credential_hmac_uq
      unique(session_id, credential_hmac);

  -- Replace the immutable columns trigger from 23/01_session_credential.up.sql
  drop trigger immutable_columns on session_credential;
  create trigger immutable_columns before update on session_credential
    for each row execute procedure immutable_columns('session_id', 'credential', 'key_id', 'credential_hmac');
  
  -- session_credentials_hmac_credential sets the credential_hmac
  -- to digest(credential, 'sha256')
  create function session_credentials_hmac_credential()
    returns trigger
  as $$
  begin
    new.credential_hmac = digest(new.credential, 'sha256');
    return new;
  end;
  $$ language plpgsql;

  create trigger session_credentials_hmac_credential before insert on session_credential
    for each row execute procedure session_credentials_hmac_credential();

commit;
