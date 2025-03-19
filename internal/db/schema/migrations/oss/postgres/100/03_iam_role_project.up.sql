-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table iam_role_project (
    public_id wt_role_id primary key
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
    create_time wt_timestamp,
    update_time wt_timestamp,
    constraint iam_role_project_name_scope_id_uq
        unique(name, scope_id)
  );
  comment on table iam_role_project is
    'iam_role_project is a subtype table of the iam_role table. It is used to store roles that are scoped to a project.';

  create trigger insert_role_subtype before insert on iam_role_project
    for each row execute procedure insert_role_subtype();

  create trigger default_create_time_column before insert on iam_role_project
    for each row execute procedure default_create_time();
  
  create trigger update_time_column before update on iam_role_project
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on iam_role_project
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on iam_role_project
    for each row execute procedure immutable_columns('scope_id', 'create_time');

commit;