-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table session_credential_dynamic (
    session_id wt_public_id not null
      constraint session_fkey
        references session (public_id)
        on delete cascade
        on update cascade,
    library_id wt_public_id not null
      constraint credential_library_fkey
        references credential_library (public_id)
        on delete cascade
        on update cascade,
    credential_id wt_public_id
      constraint credential_dynamic_fkey
        references credential_dynamic (public_id)
        on delete cascade
        on update cascade,
    credential_purpose text not null
      constraint credential_purpose_fkey
        references credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    primary key(session_id, library_id, credential_purpose),
    create_time wt_timestamp,
    constraint session_credential_dynamic_credential_id_uq
      unique(credential_id)
  );
  comment on table session_credential_dynamic is
    'session_credential_dynamic is a join table between the session and dynamic credential tables. '
    'It also contains the credential purpose the relationship represents.';

  create trigger default_create_time_column before insert on session_credential_dynamic
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on session_credential_dynamic
    for each row execute procedure immutable_columns('session_id', 'library_id', 'credential_purpose', 'create_time');

  -- revoke_credentials revokes any active credentials for a session when the
  -- session enters the canceling or terminated states.
  create function revoke_credentials() returns trigger
  as $$
  begin
    if new.state in ('canceling', 'terminated') then
      update credential_vault_credential
         set status = 'revoke'
       where session_id = new.session_id
         and status = 'active';
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger revoke_credentials after insert on session_state
    for each row execute procedure revoke_credentials();

commit;
