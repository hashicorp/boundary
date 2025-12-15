-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table auth_oidc_managed_group (
  public_id wt_public_id primary key,
  auth_method_id wt_public_id not null,
  name wt_name,
  description wt_description,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  filter wt_bexprfilter not null,
  -- Ensure that this managed group relates to an oidc auth method, as opposed
  -- to other types
  constraint auth_oidc_method_fkey
    foreign key (auth_method_id) -- fk1
      references auth_oidc_method (public_id)
      on delete cascade
      on update cascade,
  -- Ensure it relates to an abstract managed group
  constraint auth_managed_group_fkey
    foreign key (auth_method_id, public_id) -- fk2
      references auth_managed_group (auth_method_id, public_id)
      on delete cascade
      on update cascade,
  constraint auth_oidc_managed_group_auth_method_id_name_uq
    unique(auth_method_id, name)
);
comment on table auth_oidc_managed_group is
'auth_oidc_managed_group entries are subtypes of auth_managed_group and represent an oidc managed group.';

-- Define the immutable fields of auth_oidc_managed_group
create trigger immutable_columns before update on auth_oidc_managed_group
  for each row execute procedure immutable_columns('public_id', 'auth_method_id', 'create_time');

-- Populate create time on insert
create trigger default_create_time_column before insert on auth_oidc_managed_group
  for each row execute procedure default_create_time();

-- Generate update time on update
create trigger update_time_column before update on auth_oidc_managed_group
  for each row execute procedure update_time_column();

-- Update version when something changes
create trigger update_version_column after update on auth_oidc_managed_group
  for each row execute procedure update_version_column();

-- Add into the base table when inserting into the concrete table
create trigger insert_managed_group_subtype before insert on auth_oidc_managed_group
  for each row execute procedure insert_managed_group_subtype();

-- Ensure that deletions in the oidc subtype result in deletions to the base
-- table.
create trigger delete_managed_group_subtype after delete on auth_oidc_managed_group
  for each row execute procedure delete_managed_group_subtype();

-- The tickets for oplog are the subtypes not the base types because no updates
-- are done to any values in the base types.
insert into oplog_ticket
  (name, version)
values
  ('auth_oidc_managed_group', 1);

commit;
