-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  alter table host_plugin_host
    add column external_name text
      -- As it currently stands, AWS restricts EC2 Instance names to 256 UTF-8
      -- characters. Azure restricts their VM resource names to, at most, 64
      -- characters, and also have a list of disallowed runes.
      --
      -- These constraints follow the lowest common denominator between both
      -- providers for maximum compatibility. They are also synced with their
      -- logical counterpart (see `NewHost` in internal/host/plugin/host.go) to
      -- prevent a situation where a bad name could make an update job stop
      -- working.
      constraint external_name_only_has_printable_characters
        check (length(external_name) > 0 and external_name !~ '[^[:print:]]')
      constraint external_name_has_max_256_characters
        check (length(external_name) > 0 and length(external_name) <= 256);

  -- Replaces view from 44/02_hosts.up.sql
  drop view host_plugin_host_with_value_obj_and_set_memberships;
  create view host_plugin_host_with_value_obj_and_set_memberships as
  select
    h.public_id,
    h.catalog_id,
    h.external_id,
    h.external_name,
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
