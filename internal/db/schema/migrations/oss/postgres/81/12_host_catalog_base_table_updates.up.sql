-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add create_time and update_time to host_catalog table.
  alter table host_catalog add column create_time wt_timestamp;
  alter table host_catalog add column update_time wt_timestamp;

  -- Update rows with current values from the subtype host catalog tables.
  with sub_host_catalog as (
    select public_id,
           create_time,
           update_time
      from static_host_catalog
     union
    select public_id,
           create_time,
           update_time
      from host_plugin_catalog
  )
  update host_catalog
     set create_time = sub_host_catalog.create_time,
         update_time = sub_host_catalog.update_time
    from sub_host_catalog
   where host_catalog.public_id = sub_host_catalog.public_id;

  alter table host_catalog
    alter column create_time set not null,
    alter column update_time set not null;

  -- Replace the insert trigger to also set the create_time
  -- Replaces the insert_host_catalog_subtype function defined in 44/02_hosts.up.sql
   create or replace function insert_host_catalog_subtype() returns trigger
  as $$
  begin
    insert into host_catalog
      (public_id, project_id, name, create_time)
    values
      (new.public_id, new.project_id, new.name, new.create_time);
    return new;
  end;
  $$ language plpgsql;

  -- Add trigger to update the new update_time column on every subtype update.
  create function update_host_catalog_table_update_time() returns trigger
  as $$
  begin
    update host_catalog set update_time = now() where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_host_catalog_table_update_time() is
    'update_host_catalog_table_update_time is used to automatically update the update_time '
    'of the base table whenever one of the subtype tables are updated';

  -- Add triggers to subtype tables
  create trigger update_host_catalog_table_update_time before update on static_host_catalog
    for each row execute procedure update_host_catalog_table_update_time();
  create trigger update_host_catalog_table_update_time before update on host_plugin_catalog
    for each row execute procedure update_host_catalog_table_update_time();

  -- Add new indexes for the create and update time queries.
  create index host_catalog_create_time_public_id_idx
      on host_catalog (create_time desc, public_id desc);
  create index host_catalog_update_time_public_id_idx
      on host_catalog (update_time desc, public_id desc);

  analyze host_catalog;

commit;
