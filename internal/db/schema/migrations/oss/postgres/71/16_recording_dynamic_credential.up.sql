-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table recording_dynamic_credential (
    recording_id wt_public_id not null
      constraint recording_session_fk
        references recording_session (public_id)
        on delete cascade
        on update cascade,
    credential_vault_store_hst_id wt_url_safe_id not null
      constraint credential_vault_store_hst_fk
        references credential_vault_store_hst (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    credential_library_hst_id wt_url_safe_id not null
      constraint credential_library_history_base_fk
        references credential_library_history_base (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    credential_purpose text not null
      constraint credential_purpose_fkey
        references credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    primary key(recording_id, credential_vault_store_hst_id, credential_library_hst_id, credential_purpose)
  );
  comment on table recording_dynamic_credential is
    'recording_dynamic_credential table is a join table that associates a session recording with '
    'a credential library, the credential library''s credential store, '
    'and the purpose of the credential produced by the library '
    'along with the values of those entities at the time of the recording. '
    'These values are also stored in the BSR file.';

  -- Updated in 99/01_credential_vault_library_refactor.up.sql
  create function insert_recording_dynamic_credentials() returns trigger
  as $$
  begin
    with
    session_recording(session_id, recording_id) as (
      select session_id, public_id
        from recording_session
       where session_id = new.session_id
    ),
    session_dynamic_creds(library_id, purpose, recording_id) as (
      select library_id, credential_purpose, recording_id
        from session_credential_dynamic
        join session_recording using (session_id)
    ),
    library_history(public_id, store_id, library_hst_id, valid_range) as (
      select public_id, store_id, history_id, valid_range
        from credential_vault_library_hst
       union
      select public_id, store_id, history_id, valid_range
        from credential_vault_ssh_cert_library_hst
    ),
    final(recording_id, library_id, store_id, library_hst_id, store_hst_id, cred_purpose) as (
      select sdc.recording_id, lib.public_id, lib.store_id, lib.library_hst_id, store_hst.history_id, sdc.purpose
        from library_history as lib
        join credential_vault_store_hst as store_hst on lib.store_id = store_hst.public_id
         and store_hst.valid_range @> current_timestamp
        join session_dynamic_creds as sdc on lib.public_id = sdc.library_id
       where lib.public_id in (select library_id from session_dynamic_creds)
         and lib.valid_range @> current_timestamp
    )
    insert into recording_dynamic_credential
          (recording_id, credential_vault_store_hst_id, credential_library_hst_id, credential_purpose)
    select recording_id, store_hst_id,                  library_hst_id,            cred_purpose
      from final;
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_recording_dynamic_credentials is
    'insert_recording_dynamic_credentials is an after insert trigger for the recording_session table.';

  create trigger insert_recording_dynamic_credentials after insert on recording_session
    for each row execute procedure insert_recording_dynamic_credentials();

commit;
