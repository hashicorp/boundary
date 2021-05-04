begin;

  create table target_credential_purpose_enm (
    name text primary key
      constraint only_predefined_credential_purposes_allowed
      check (
        name in (
          'application',
          'ingress',
          'egress'
        )
      )
  );
  comment on table target_credential_purpose_enm is
    'target_credential_purpose_enm is an enumeration table for credential purposes. '
    'It contains rows for representing the application, egress, and ingress credential purposes.';

  insert into target_credential_purpose_enm (name)
  values
    ('application'),
    ('ingress'),
    ('egress');

  create table target_credential_library (
    target_id wt_public_id not null
      constraint target_fkey
        references target (public_id)
        on delete cascade
        on update cascade,
    credential_library_id wt_public_id not null
      constraint credential_library_fkey
        references credential_library (public_id)
        on delete cascade
        on update cascade,
    credential_purpose text not null
      constraint target_credential_purpose_enm_fkey
        references target_credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    primary key(target_id, credential_library_id, credential_purpose)
  );
  comment on table target_credential_library is
    'target_credential_library is a join table between the target and credential_library tables. '
    'It also contains the credential purpose the relationship represents.';

  create trigger default_create_time_column before insert on target_credential_library
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on target_credential_library
    for each row execute procedure immutable_columns('target_id', 'credential_library_id', 'credential_purpose', 'create_time');

commit;
