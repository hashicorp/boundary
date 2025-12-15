-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- dropping these foreign keys because they were never needed
  alter table host_plugin_catalog drop constraint iam_scope_fkey;
  alter table static_host_catalog drop constraint static_host_catalog_scope_id_fkey;

  alter table host_catalog rename column scope_id to project_id;
  alter table host_catalog rename constraint host_catalog_scope_id_name_uq to host_catalog_project_id_name_uq;
  alter table host_catalog rename constraint host_catalog_scope_id_public_id_key to host_catalog_project_id_public_id_uq;
  drop trigger immutable_columns on host_catalog;
  create trigger immutable_columns before update on host_catalog
    for each row execute function immutable_columns('public_id', 'project_id');

  -- insert_host_catalog_subtype() is a before insert trigger function for
  -- subtypes of host_catalog.
  -- Replaces the insert_host_catalog_subtype function defined in 20/04_host.up.sql
  -- Replaced in 80/10_host_catalog_base_table_updates.up.sql
  create or replace function insert_host_catalog_subtype() returns trigger
  as $$
  begin
    insert into host_catalog
      (public_id, project_id, name)
    values
      (new.public_id, new.project_id, new.name);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_host_catalog_subtype() is
    'insert_host_catalog_subtype() is a before insert trigger function that should be added to all host_catalog subtype tables.';

  alter table static_host_catalog rename column scope_id to project_id;
  alter table static_host_catalog rename constraint static_host_catalog_scope_id_name_key to static_host_catalog_project_id_name_uq;
  drop trigger immutable_columns on static_host_catalog;
  create trigger immutable_columns before update on static_host_catalog
    for each row execute function immutable_columns('public_id', 'project_id', 'create_time');

  alter table host_plugin_catalog rename column scope_id to project_id;
  alter table host_plugin_catalog rename constraint host_plugin_catalog_scope_id_name_uq to host_plugin_catalog_project_id_name_uq;
  drop trigger immutable_columns on host_plugin_catalog;
  create trigger immutable_columns before update on host_plugin_catalog
    for each row execute function immutable_columns('public_id', 'project_id', 'plugin_id', 'create_time');

  -- target_host_set_scope_valid() is a before insert trigger function for target_host_set
  -- Replaces target_host_set_scope_valid defined in 0/40_targets.up.sql
  -- Replaced in 44/03_targets.up.sql
  create or replace function target_host_set_scope_valid() returns trigger
  as $$
  declare
    host_set_project_id wt_scope_id;
    target_project_id wt_scope_id;
  begin

    select hc.project_id into host_set_project_id
      from host_set hs
      join host_catalog hc on hs.catalog_id = hc.public_id
     where hs.public_id = new.host_set_id;

    select target.scope_id into target_project_id
      from target
     where target.public_id = new.target_id;

    if target_project_id = host_set_project_id then
      return new;
    end if;
    raise exception 'target and host set are not in the same scope' using
          errcode = '23000',
          schema  = tg_table_schema,
          table   = tg_table_name;

  end;
  $$ language plpgsql;

  -- update views
  drop view host_plugin_catalog_with_secret;
  -- Recreated in 56/02_add_data_key_foreign_key_references.up.sql
  create view host_plugin_catalog_with_secret as
  select
    hc.public_id,
    hc.project_id,
    hc.plugin_id,
    hc.name,
    hc.description,
    hc.create_time,
    hc.update_time,
    hc.version,
    hc.secrets_hmac,
    hc.attributes,
    hcs.secret,
    hcs.key_id,
    hcs.create_time as persisted_create_time,
    hcs.update_time as persisted_update_time
  from
    host_plugin_catalog hc
      left outer join host_plugin_catalog_secret hcs   on hc.public_id = hcs.catalog_id;
  comment on view host_plugin_catalog_with_secret is
    'host plugin catalog with its associated persisted data';

  -- Replaces view from 20/08_plugin_host_views.up.sql
  -- Replaced in 69/01_plugin_host_external_name.up.sql
  drop view host_plugin_host_with_value_obj_and_set_memberships;
  create view host_plugin_host_with_value_obj_and_set_memberships as
  select
    h.public_id,
    h.catalog_id,
    h.external_id,
    hc.project_id,
    hc.plugin_id,
    h.name,
    h.description,
    h.create_time,
    h.update_time,
    h.version,
    -- the string_agg(..) column will be null if there are no associated value objects
    string_agg(distinct host(hip.address), '|') as ip_addresses,
    string_agg(distinct hdns.name, '|') as dns_names,
    string_agg(distinct hpsm.set_id, '|') as set_ids
  from
    host_plugin_host h
      join host_plugin_catalog hc                  on h.catalog_id = hc.public_id
      left outer join host_ip_address hip          on h.public_id = hip.host_id
      left outer join host_dns_name hdns           on h.public_id = hdns.host_id
      left outer join host_plugin_set_member hpsm  on h.public_id = hpsm.host_id
  group by h.public_id, hc.plugin_id, hc.project_id;
  comment on view host_plugin_host_with_value_obj_and_set_memberships is
    'host plugin host with its associated value objects';

commit;
