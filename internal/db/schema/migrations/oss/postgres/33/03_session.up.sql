-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table session_credential_static (
    session_id wt_public_id not null
      constraint session_fkey
        references session (public_id)
        on delete cascade
        on update cascade,
    credential_static_id wt_public_id
      constraint credential_static_fkey
        references credential_static (public_id)
        on delete cascade
        on update cascade,
    credential_purpose text not null
      constraint credential_purpose_fkey
        references credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    primary key(session_id, credential_static_id, credential_purpose),
    create_time wt_timestamp
  );
  comment on table session_credential_dynamic is
    'session_credential_static is a join table between the session and static credential tables. '
    'It also contains the credential purpose the relationship represents.';

  create trigger default_create_time_column before insert on session_credential_static
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on session_credential_static
    for each row execute procedure immutable_columns('session_id', 'credential_static_id', 'credential_purpose', 'create_time');

commit;
