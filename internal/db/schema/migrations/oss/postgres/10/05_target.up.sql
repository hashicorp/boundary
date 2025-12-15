-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

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
      constraint credential_purpose_enm_fkey
        references credential_purpose_enm (name)
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

  -- replaced in 33/02_target.up.sql
  -- target_library provides the store id along with the other data stored in
  -- target_credential_library
  create view target_library
  as
  select
    tcl.target_id,
    tcl.credential_library_id,
    tcl.credential_purpose,
    cl.store_id
  from
    target_credential_library tcl,
    credential_library cl
  where
    cl.public_id = tcl.credential_library_id;

commit;
