-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- for the following foreign key constraint to work,
  -- we need to ensure that all canonical_grant values in iam_role_grant exist in iam_grant.
  insert into iam_grant (canonical_grant)
  select canonical_grant
    from iam_role_grant
      on conflict do nothing;

  -- Add a foreign key constraint to the iam_role_grant table to ensure that the canonical_grant exists in the iam_grant table.
  -- Alter to add foreign key constraint to the iam_role_grant table defined in 01/06_iam.up.sql
  alter table iam_role_grant
    add constraint iam_grant_fkey
     foreign key (canonical_grant)
        references iam_grant(canonical_grant)
        on delete cascade
        on update cascade;

  -- remove iam_role_grant_scope and all cross-table dependencies
  drop table iam_role_grant_scope cascade;
  drop trigger cascade_deletion_iam_scope_to_iam_role_grant_scope on iam_scope;

  -- remove name, description, version from iam_role
  alter table iam_role
    drop column name,
    drop column description,
    drop column version;

commit;