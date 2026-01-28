-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table target
    add constraint iam_scope_project_fkey
      foreign key (project_id)
        references iam_scope_project (scope_id)
        on delete cascade
        on update cascade,
    drop constraint target_scope_id_fkey
  ;

  alter table session rename constraint session_target_id_fkey to target_fkey;
  alter table target_host_set rename constraint target_host_set_target_id_fkey to target_fkey;
  alter table target_tcp rename constraint target_tcp_public_id_fkey to target_fkey;

  drop function target_scope_valid cascade;

commit;
