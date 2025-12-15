-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table session_credential (
    session_id wt_public_id not null
      constraint session_fkey
        references session (public_id)
        on delete cascade
        on update cascade,
    credential bytea not null -- encrypted
      constraint credential_must_not_be_empty
        check(length(credential) > 0),
    key_id text not null
      constraint kms_database_key_version_fkey
        references kms_database_key_version (private_id)
        on delete restrict
        on update cascade,
    -- Constraint dropped in 43/01_session_credentials.up.sql    
    constraint session_credential_session_id_credential_uq
        unique(session_id, credential)
  );
  comment on table session_credential is
    'session_credential is a table where each row contains a credential to be used by '
    'by a worker when a connection is established for the session_id.';

  -- this trigger is updated in 56/05_mutable_ciphertext_columns.up.sql
  create trigger immutable_columns before update on session_credential
    for each row execute procedure immutable_columns('session_id', 'credential', 'key_id');

  -- delete_credentials deletes all credentials for a session when the
  -- session enters the canceling or terminated states.
  create function delete_session_credentials() returns trigger
  as $$
  begin
    if new.state in ('canceling', 'terminated') then
      delete from session_credential
        where session_id = new.session_id;
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger delete_session_credentials after insert on session_state
    for each row execute procedure delete_session_credentials();

commit;
