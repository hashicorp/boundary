-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- target_static_credential does not follow the normal table naming convention of target_credential_static
  create table target_static_credential (
    target_id wt_public_id not null
      constraint target_fkey
        references target (public_id)
        on delete cascade
        on update cascade,
    credential_static_id wt_public_id not null
      constraint credential_static_fkey
        references credential_static (public_id)
        on delete cascade
        on update cascade,
    credential_purpose text not null
      constraint credential_purpose_enm_fkey
        references credential_purpose_enm (name)
        on delete restrict
        on update cascade,
    create_time wt_timestamp,
    primary key(target_id, credential_static_id, credential_purpose)
  );
  comment on table target_static_credential is
    'target_static_credential is a join table between the target, credential_static, and credential_purpose_enm tables. '
    'A row in the target_static_credential table represents the assignment of a static credential to a target for the specified purpose.';

  create trigger default_create_time_column before insert on target_static_credential
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on target_static_credential
    for each row execute procedure immutable_columns('target_id', 'credential_static_id', 'credential_purpose', 'create_time');

  -- replaces view from 10/05_target.up.sql
  drop view target_library;
  -- target_credential_source provides the store id along with the other data stored in
  -- target_credential_library and target_static_credential
  create view target_credential_source
  as
    select
      tcl.target_id,
      tcl.credential_library_id as credential_source_id,
      tcl.credential_purpose,
      cl.store_id,
      'library' as type
    from
      target_credential_library tcl,
      credential_library cl
    where
      cl.public_id = tcl.credential_library_id
    union
    select
      tcs.target_id,
      tcs.credential_static_id as credential_source_id,
      tcs.credential_purpose,
      cst.store_id,
      'static' as type
    from
      target_static_credential tcs,
      credential_static cst
    where
      cst.public_id = tcs.credential_static_id;
  comment on view target_credential_source is
    'target_credential_source is a view where each row contains a credential source and the id of the parent credential store. '
    'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

  create view credential_source_all_types
  as
    select
      public_id,
      'library' as type
    from
      credential_library
    union
    select
      public_id,
      'static' as type
    from
      credential_static;
  comment on view credential_source_all_types is
    'credential_source_all_types is a view where each row contains the credential source id and type.';

commit;
