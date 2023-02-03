-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

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
