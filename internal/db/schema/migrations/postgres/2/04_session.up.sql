begin;

  create table session_credential_library (
    session_id wt_public_id not null
      constraint session_fk
        references session (public_id)
        on delete cascade
        on update cascade,
    credential_library_id wt_public_id not null
      constraint credential_library_fk
        references credential_library (public_id)
        on delete cascade
        on update cascade,
    target_credential_type text not null
      constraint target_credential_type_fk
        references target_credential_type_enm (name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    primary key(session_id, credential_library_id, target_credential_type)
  );

  create trigger default_create_time_column before insert on session_credential_library
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on session_credential_library
    for each row execute procedure immutable_columns('session_id', 'credential_library_id', 'target_credential_type', 'create_time');

commit;
