-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table host_catalog
    add constraint iam_scope_project_fkey
      foreign key (project_id)
        references iam_scope_project (scope_id)
        on delete cascade
        on update cascade,
    drop constraint host_catalog_scope_id_fkey
  ;

  alter table host rename constraint host_catalog_id_fkey to host_catalog_fkey;
  alter table host_set rename constraint host_set_catalog_id_fkey to host_catalog_fkey;

  alter table static_host_catalog
    add constraint host_catalog_fkey
      foreign key (project_id, public_id)
        references host_catalog (project_id, public_id)
        on delete cascade
        on update cascade,
    drop constraint if exists static_host_catalog_scope_id_fkey1, -- pg 11
    drop constraint if exists static_host_catalog_scope_id_public_id_fkey -- pg 12, 13, 14
  ;

commit;

