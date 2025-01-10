-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table iam_role_project (
    public_id wt_role_id not null primary key
      constraint iam_role_fkey
        references iam_role(public_id)
        on delete cascade
        on update cascade,
    scope_id wt_scope_id not null
      constraint iam_scope_project_fkey
        references iam_scope_project(scope_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    version wt_version,
    grant_scope_update_time wt_timestamp
  );

  create trigger insert_iam_role_project_grant_scope_update_time before update on iam_role_project
    for each row execute procedure insert_grant_scope_update_time();  

commit;