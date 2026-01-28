-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- We are adding the name to the base host catalog type. This allows the db
  -- to ensure that catalog names are unique in a scope across all subtypes.
  alter table host_catalog
    add column name wt_name;

  alter table host_catalog
    add constraint host_catalog_scope_id_name_uq
      unique (scope_id, name);

  -- Now that we've added the name column to the base type, we copy
  -- the name from the static host catalog table into the base table.
  update host_catalog
  set name = st.name
  from
    static_host_catalog st
  where
    host_catalog.public_id = st.public_id and
    st.name is not null;

  -- Replace the insert_host_catalog_subtype function defined in 0/20_host.up.sql
  -- to include the name.
  -- insert_host_catalog_subtype() is a before insert trigger
  -- function for subtypes of host_catalog
  -- Replaced in 44/02_hosts.up.sql
  create or replace function insert_host_catalog_subtype() returns trigger
  as $$
  begin
    insert into host_catalog
    (public_id, scope_id, name)
    values
      (new.public_id, new.scope_id, new.name);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_host_catalog_subtype() is
    'insert_host_catalog_subtype() inserts sub type name into the base type host catalog table';

  -- Now that we are tracking the name, which is mutable, we need to also
  -- update the base table when the subtype tables are updated.
  -- update_host_catalog_subtype() is intended to be used as a before update
  -- trigger for all host catalog sub types.  The purpose is to ensure that the
  -- base table for host catalog to contain the updated names for each host catalog
  -- in order to enforce uniqueness across all host catalogs, regardless of subtype,
  -- in a given scope.
  create function update_host_catalog_subtype() returns trigger
  as $$
  begin
    update host_catalog set name = new.name where public_id = new.public_id and new.name != name;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_host_catalog_subtype() is
    'update_host_catalog_subtype() will update base host catalog type name column with new values from sub type';

  create trigger update_host_catalog_subtype before update on static_host_catalog
    for each row execute procedure update_host_catalog_subtype();

commit;
