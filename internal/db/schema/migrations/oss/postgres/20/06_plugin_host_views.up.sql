-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- host_plugin_host_set_with_value_obj is useful for reading a plugin host set with its
-- associated value objects (preferred endpoints) as columns with delimited
-- values. The delimiter depends on the value objects (e.g. if they need
-- ordering).
create view host_plugin_host_set_with_value_obj as
  select
    hs.public_id,
    hs.catalog_id,
    hc.plugin_id,
    hs.name,
    hs.description,
    hs.create_time,
    hs.update_time,
    hs.last_sync_time,
    hs.need_sync,
    hs.sync_interval_seconds,
    hs.version,
    hs.attributes,
    -- the string_agg(..) column will be null if there are no associated value objects
    string_agg(distinct concat_ws('=', hspe.priority, hspe.condition), '|') as preferred_endpoints,
    string_agg(distinct hpsm.host_id, '|') as host_ids
  from
    host_plugin_set hs
    join host_plugin_catalog hc                        on hs.catalog_id = hc.public_id
    left outer join host_set_preferred_endpoint hspe   on hs.public_id = hspe.host_set_id
    left outer join host_plugin_set_member hpsm        on hs.public_id = hpsm.set_id
  group by hs.public_id, hc.plugin_id;
comment on view host_plugin_host_set_with_value_obj is
  'host plugin host set with its associated value objects';

-- REPLACED in 10_plugin_host_secrets_hmac.up.sql
create view host_plugin_catalog_with_secret as
select
  hc.public_id,
  hc.scope_id,
  hc.plugin_id,
  hc.name,
  hc.description,
  hc.create_time,
  hc.update_time,
  hc.version,
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

-- REPLACED in 20/08_plugin_host_views.up.sql
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