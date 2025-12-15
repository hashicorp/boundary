-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table recording_static_credential (
    recording_id wt_public_id not null
      constraint recording_session_fk
        references recording_session (public_id)
        on delete cascade
        on update cascade,
    credential_static_store_hst_id wt_url_safe_id not null
      constraint credential_static_store_hst_fk
        references credential_static_store_hst (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    credential_static_hst_id wt_url_safe_id not null
      constraint credential_static_history_base_fk
        references credential_static_history_base (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    credential_purpose text not null
      constraint credential_purpose_fkey
        references credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    primary key(recording_id, credential_static_store_hst_id, credential_static_hst_id, credential_purpose)
  );
  comment on table recording_static_credential is
    'recording_static_credential table is a join table that associates a session recording with '
    'a static credential, the static credential''s static credential store, and the credential''s purpose '
    'along with the values of those entities at the time of the recording. '
    'These values are also stored in the BSR file.';

  -- This function is updated in 98/01_credential_static_username_password_domain_credential.up.sql
  create function insert_recording_static_credentials() returns trigger
  as $$
  begin
    with
    session_recording(session_id, recording_id) as (
      select session_id, public_id
        from recording_session
       where session_id = new.session_id
    ),
    session_static_creds(cred_id, purpose, recording_id) as (
      select credential_static_id, credential_purpose, recording_id
        from session_credential_static
        join session_recording using (session_id)
    ),
    static_cred_history(public_id, store_id, cred_hst_id, valid_range) as (
      select public_id, store_id, history_id, valid_range
        from credential_static_json_credential_hst
       union
      select public_id, store_id, history_id, valid_range
        from credential_static_ssh_private_key_credential_hst
       union
      select public_id, store_id, history_id, valid_range
        from credential_static_username_password_credential_hst
    ),
    final(recording_id, cred_id, store_id, cred_hst_id, store_hst_id, cred_purpose) as (
      select ssc.recording_id, sc.public_id, sc.store_id, sc.cred_hst_id, store_hst.history_id, ssc.purpose
        from static_cred_history as sc
        join credential_static_store_hst as store_hst on sc.store_id = store_hst.public_id
         and store_hst.valid_range @> current_timestamp
        join session_static_creds as ssc on sc.public_id = ssc.cred_id
       where sc.public_id in (select cred_id from session_static_creds)
         and sc.valid_range @> current_timestamp
    )
    insert into recording_static_credential
          (recording_id, credential_static_store_hst_id, credential_static_hst_id, credential_purpose)
    select recording_id, store_hst_id,                   cred_hst_id,              cred_purpose
      from final;

    return new;
  end;
  $$ language plpgsql;
  comment on function insert_recording_static_credentials is
    'insert_recording_static_credentials is an after insert trigger for the recording_session table.';

  create trigger insert_recording_static_credentials after insert on recording_session
    for each row execute procedure insert_recording_static_credentials();

commit;
