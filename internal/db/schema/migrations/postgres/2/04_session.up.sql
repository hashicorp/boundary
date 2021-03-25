begin;

  create table session_credential_library (
    session_id wt_public_id not null
      constraint session_fk
        references session (public_id)
        on delete cascade
        on update cascade,
    credential_id wt_public_id not null
      constraint credential_fk
        references credential (public_id)
        on delete cascade
        on update cascade,
    credential_library_id wt_public_id not null
      constraint credential_library_fk
        references credential_library (public_id)
        on delete cascade
        on update cascade,
    target_credential_purpose text not null
      constraint target_credential_purpose_fk
        references target_credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    primary key(session_id, credential_id, credential_library_id, target_credential_purpose)
  );
  comment on table session_credential_library is
    'session_credential_library is a join table between the session, credential, and credential_library tables. '
    'It also contains the credential purpose the relationship represents.';

  create trigger default_create_time_column before insert on session_credential_library
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on session_credential_library
    for each row execute procedure immutable_columns('session_id', 'credential_id', 'credential_library_id', 'target_credential_purpose', 'create_time');

commit;
