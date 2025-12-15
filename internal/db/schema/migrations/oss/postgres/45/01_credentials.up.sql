-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table credential_store
    add constraint iam_scope_project_fkey
      foreign key (project_id)
        references iam_scope_project (scope_id)
        on delete cascade
        on update cascade,
    drop constraint iam_scope_fkey
  ;

commit;
