-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- drop constraint so we can migrate enm values
  alter table credential_purpose_enm
    drop constraint only_predefined_credential_purposes_allowed;

  -- drop immutable columns so we can migrate enm values
  drop trigger immutable_columns on target_credential_library;
  drop trigger immutable_columns on session_credential_dynamic;
  drop trigger immutable_columns on target_static_credential;
  drop trigger immutable_columns on session_credential_static;

  -- update egress to injected_application
  update credential_purpose_enm
     set name = 'injected_application'
   where name = 'egress';

  -- update application to brokered
  update credential_purpose_enm
     set name = 'brokered'
   where name = 'application';

  -- delete ingress as it will no longer be used
  delete from credential_purpose_enm
   where name = 'ingress';

  -- Add new constraint that only allows 'brokered' and new 'injected_application'
  -- This replaces the constraint defined in 10/03_credential.up.sql
  alter table credential_purpose_enm
    add constraint only_predefined_credential_purposes_allowed
      check (
        name in (
          'brokered',
          'injected_application'
        )
      );
  -- update comment on table   
  comment on table credential_purpose_enm is
    'credential_purpose_enm is an enumeration table for credential purposes. '
    'It contains rows for representing the brokered, and injected_application credential purposes.';

  -- replace the immutable columns
  create trigger immutable_columns before update on target_credential_library
    for each row execute procedure immutable_columns('target_id', 'credential_library_id', 'credential_purpose', 'create_time');
  create trigger immutable_columns before update on session_credential_dynamic
    for each row execute procedure immutable_columns('session_id', 'library_id', 'credential_purpose', 'create_time');

  create trigger immutable_columns before update on target_static_credential
    for each row execute procedure immutable_columns('target_id', 'credential_static_id', 'credential_purpose', 'create_time');
  create trigger immutable_columns before update on session_credential_static
      for each row execute procedure immutable_columns('session_id', 'credential_static_id', 'credential_purpose', 'create_time');

commit;
