begin;

  create table session_credential_dynamic (
    credential_id wt_public_id not null,
    library_id wt_public_id not null,
    constraint credential_dynamic_fkey
      foreign key (credential_id, library_id)
      references credential_dynamic (public_id, library_id)
      on delete cascade
      on update cascade,
    session_id wt_public_id not null
      constraint session_fkey
        references session (public_id)
        on delete cascade
        on update cascade,
    credential_purpose text not null
      constraint target_credential_purpose_fkey
        references target_credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    primary key(session_id, credential_id, library_id),
    constraint session_credential_dynamic_library_id_credential_id_uq
      unique(library_id, credential_id),
    constraint session_credential_dynamic_credential_id_uq
      unique(credential_id)
  );
  comment on table session_credential_dynamic is
    'session_credential_dynamic is a join table between the session and dynamic credential tables. '
    'It also contains the credential purpose the relationship represents.';

  create trigger default_create_time_column before insert on session_credential_dynamic
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on session_credential_dynamic
    for each row execute procedure immutable_columns('session_id', 'credential_id', 'library_id', 'credential_purpose', 'create_time');

commit;
