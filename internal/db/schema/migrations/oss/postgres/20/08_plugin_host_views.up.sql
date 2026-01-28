-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

alter table host_plugin_host
  add column version wt_version;

create trigger update_version_column after update on host_plugin_host
  for each row execute procedure update_version_column();

-- Updated view in 44/02_hosts.up.sql
-- host_plugin_host_with_value_obj_and_set_memberships is useful for reading a
-- plugin host with its associated value objects (ip addresses, dns names) and
-- set membership as columns with delimited values. The delimiter depends on
-- the value objects (e.g. if they need ordering).
drop view host_plugin_host_with_value_obj_and_set_memberships;
create view host_plugin_host_with_value_obj_and_set_memberships as
select
  h.public_id,
  h.catalog_id,
  h.external_id,
  hc.scope_id,
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
group by h.public_id, hc.plugin_id, hc.scope_id;
comment on view host_plugin_host_with_value_obj_and_set_memberships is
  'host plugin host with its associated value objects';

commit;