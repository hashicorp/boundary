// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

const (
	upsertHostCatalogSecretQuery = `
insert into host_plugin_catalog_secret
  (catalog_id, secret, key_id)
values
  (@catalog_id, @secret, @key_id)
on conflict (catalog_id) do update
  set secret  = excluded.secret,
      key_id  = excluded.key_id
returning *;
`

	deleteHostCatalogSecretQuery = `
delete from host_plugin_catalog_secret
 where catalog_id = @catalog_id;
`

	setSyncNextRunInQuery = `
select
  need_sync as sync_now,
  sync_interval_seconds,
  case
    when sync_interval_seconds is null
      then
        extract(epoch from (least(now(), last_sync_time) + ?) - now())::int
    when sync_interval_seconds > 0
      then
        extract(epoch from (least(now(), last_sync_time)) - now())::int + sync_interval_seconds
    else
      0
  end resync_in
from host_plugin_set
order by need_sync desc, last_sync_time desc
limit 1;
`

	setSyncJobQuery = `
need_sync
  or
sync_interval_seconds is null and last_sync_time <= wt_add_seconds_to_now(?)
  or
sync_interval_seconds > 0 and wt_add_seconds(sync_interval_seconds, last_sync_time) <= current_timestamp
`

	updateSyncDataQuery = `
update host_plugin_set
set
  last_sync_time = current_timestamp,
  need_sync = false
where public_id = ?
`

	estimateCountHosts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('host_plugin_host'::regclass)
`

	listHostsTemplate = `
with hosts as (
    select public_id,
           catalog_id,
           external_id,
           external_name,
           name,
           description,
           create_time,
           update_time,
           version
      from host_plugin_host
     where catalog_id = @catalog_id
  order by create_time desc, public_id desc
     limit %d
),
host_catalog as (
  select project_id,
         plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
host_ip_addresses as (
    select string_agg(distinct host(address), '|') as ip_addresses,
           host_id
      from host_ip_address
     where host_id in (select public_id from hosts)
  group by host_id
),
host_dns_names as (
    select string_agg(distinct name, '|') as dns_names,
           host_id
      from host_dns_name
     where host_id in (select public_id from hosts)
  group by host_id
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from host_plugin_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
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
                  hia.ip_addresses,
                  hdn.dns_names,
                  hsi.set_ids
             from hosts h
             join host_catalog hc       on hc.public_id = h.catalog_id
  left outer join host_ip_addresses hia on hia.host_id = h.public_id
  left outer join host_dns_names hdn    on hdn.host_id = h.public_id
  left outer join host_set_ids hsi      on hsi.host_id = h.public_id
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listHostsPageTemplate = `
with hosts as (
    select public_id,
           catalog_id,
           external_id,
           external_name,
           name,
           description,
           create_time,
           update_time,
           version
      from host_plugin_host
     where catalog_id = @catalog_id
       and (create_time, public_id) < (@last_item_create_time, @last_item_id)
  order by create_time desc, public_id desc
     limit %d
),
host_catalog as (
  select project_id,
         plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
host_ip_addresses as (
    select string_agg(distinct host(address), '|') as ip_addresses,
           host_id
      from host_ip_address
     where host_id in (select public_id from hosts)
  group by host_id
),
host_dns_names as (
    select string_agg(distinct name, '|') as dns_names,
           host_id
      from host_dns_name
     where host_id in (select public_id from hosts)
  group by host_id
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from host_plugin_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
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
                  hia.ip_addresses,
                  hdn.dns_names,
                  hsi.set_ids
             from hosts h
             join host_catalog hc       on hc.public_id = h.catalog_id
  left outer join host_ip_addresses hia on hia.host_id = h.public_id
  left outer join host_dns_names hdn    on hdn.host_id = h.public_id
  left outer join host_set_ids hsi      on hsi.host_id = h.public_id
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listHostsRefreshTemplate = `
with hosts as (
    select public_id,
           catalog_id,
           external_id,
           external_name,
           name,
           description,
           create_time,
           update_time,
           version
      from host_plugin_host
     where catalog_id = @catalog_id
       and update_time > @updated_after_time
  order by update_time desc, public_id desc
     limit %d
),
host_catalog as (
  select project_id,
         plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
host_ip_addresses as (
    select string_agg(distinct host(address), '|') as ip_addresses,
           host_id
      from host_ip_address
     where host_id in (select public_id from hosts)
  group by host_id
),
host_dns_names as (
    select string_agg(distinct name, '|') as dns_names,
           host_id
      from host_dns_name
     where host_id in (select public_id from hosts)
  group by host_id
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from host_plugin_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
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
                  hia.ip_addresses,
                  hdn.dns_names,
                  hsi.set_ids
             from hosts h
             join host_catalog hc       on hc.public_id = h.catalog_id
  left outer join host_ip_addresses hia on hia.host_id = h.public_id
  left outer join host_dns_names hdn    on hdn.host_id = h.public_id
  left outer join host_set_ids hsi      on hsi.host_id = h.public_id
)
  select *
    from final
order by update_time desc, public_id desc;
`

	listHostsRefreshPageTemplate = `
with hosts as (
    select public_id,
           catalog_id,
           external_id,
           external_name,
           name,
           description,
           create_time,
           update_time,
           version
      from host_plugin_host
     where catalog_id = @catalog_id
       and update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
  order by update_time desc, public_id desc
     limit %d
),
host_catalog as (
  select project_id,
         plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
host_ip_addresses as (
    select string_agg(distinct host(address), '|') as ip_addresses,
           host_id
      from host_ip_address
     where host_id in (select public_id from hosts)
  group by host_id
),
host_dns_names as (
    select string_agg(distinct name, '|') as dns_names,
           host_id
      from host_dns_name
     where host_id in (select public_id from hosts)
  group by host_id
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from host_plugin_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
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
                  hia.ip_addresses,
                  hdn.dns_names,
                  hsi.set_ids
             from hosts h
             join host_catalog hc       on hc.public_id = h.catalog_id
  left outer join host_ip_addresses hia on hia.host_id = h.public_id
  left outer join host_dns_names hdn    on hdn.host_id = h.public_id
  left outer join host_set_ids hsi      on hsi.host_id = h.public_id
)
  select *
    from final
order by update_time desc, public_id desc;
`

	estimateCountHostSets = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('host_plugin_set'::regclass)
`

	listSetsTemplate = `
with host_sets as (
    select public_id,
           catalog_id,
           name,
           description,
           create_time,
           update_time,
           last_sync_time,
           need_sync,
           sync_interval_seconds,
           version,
           attributes
      from host_plugin_set
     where catalog_id = @catalog_id
  order by create_time desc, public_id desc
     limit %d
),
host_catalog as (
  select plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
preferred_endpoints as (
    select string_agg(distinct concat_ws('=', priority, condition), '|') as preferred_endpoints,
           host_set_id            
      from host_set_preferred_endpoint
     where host_set_id in (select public_id from host_sets)
  group by host_set_id
),
host_set_members as (
    select string_agg(distinct host_id, '|') as host_ids,
           set_id            
      from host_plugin_set_member
     where set_id in (select public_id from host_sets)
  group by set_id
), 
final as (
           select hs.public_id,
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
                  ppe.preferred_endpoints,
                  hsm.host_ids
             from host_sets hs
             join host_catalog hc         on hc.public_id = hs.catalog_id
  left outer join preferred_endpoints ppe on ppe.host_set_id = hs.public_id
  left outer join host_set_members hsm    on hsm.set_id = hs.public_id
)
  select *  
    from final
order by create_time desc, public_id desc;
`

	listSetsPageTemplate = `
with host_sets as (
    select public_id,
           catalog_id,
           name,
           description,
           create_time,
           update_time,
           last_sync_time,
           need_sync,
           sync_interval_seconds,
           version,
           attributes
      from host_plugin_set
     where catalog_id = @catalog_id
       and (create_time, public_id) < (@last_item_create_time, @last_item_id)
  order by create_time desc, public_id desc
     limit %d
),
host_catalog as (
  select plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
preferred_endpoints as (
    select string_agg(distinct concat_ws('=', priority, condition), '|') as preferred_endpoints,
           host_set_id            
      from host_set_preferred_endpoint
     where host_set_id in (select public_id from host_sets)
  group by host_set_id
),
host_set_members as (
    select string_agg(distinct host_id, '|') as host_ids,
           set_id            
      from host_plugin_set_member
     where set_id in (select public_id from host_sets)
  group by set_id
), 
final as (
           select hs.public_id,
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
                  ppe.preferred_endpoints,
                  hsm.host_ids
             from host_sets hs
             join host_catalog hc         on hc.public_id = hs.catalog_id
  left outer join preferred_endpoints ppe on ppe.host_set_id = hs.public_id
  left outer join host_set_members hsm    on hsm.set_id = hs.public_id
)
  select *  
    from final
order by create_time desc, public_id desc;
`

	listSetsRefreshTemplate = `
with host_sets as (
    select public_id,
           catalog_id,
           name,
           description,
           create_time,
           update_time,
           last_sync_time,
           need_sync,
           sync_interval_seconds,
           version,
           attributes
      from host_plugin_set
     where catalog_id = @catalog_id
       and update_time > @updated_after_time
  order by update_time desc, public_id desc
     limit %d
),
host_catalog as (
  select plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
preferred_endpoints as (
    select string_agg(distinct concat_ws('=', priority, condition), '|') as preferred_endpoints,
           host_set_id            
      from host_set_preferred_endpoint
     where host_set_id in (select public_id from host_sets)
  group by host_set_id
),
host_set_members as (
    select string_agg(distinct host_id, '|') as host_ids,
           set_id            
      from host_plugin_set_member
     where set_id in (select public_id from host_sets)
  group by set_id
), 
final as (
           select hs.public_id,
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
                  ppe.preferred_endpoints,
                  hsm.host_ids
             from host_sets hs
             join host_catalog hc         on hc.public_id = hs.catalog_id
  left outer join preferred_endpoints ppe on ppe.host_set_id = hs.public_id
  left outer join host_set_members hsm    on hsm.set_id = hs.public_id
)
  select *  
    from final
order by update_time desc, public_id desc;
`

	listSetsRefreshPageTemplate = `
with host_sets as (
    select public_id,
           catalog_id,
           name,
           description,
           create_time,
           update_time,
           last_sync_time,
           need_sync,
           sync_interval_seconds,
           version,
           attributes
      from host_plugin_set
     where catalog_id = @catalog_id
       and update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
  order by update_time desc, public_id desc
     limit %d
),
host_catalog as (
  select plugin_id,
         public_id
    from host_plugin_catalog
   where public_id = @catalog_id
),
preferred_endpoints as (
    select string_agg(distinct concat_ws('=', priority, condition), '|') as preferred_endpoints,
           host_set_id            
      from host_set_preferred_endpoint
     where host_set_id in (select public_id from host_sets)
  group by host_set_id
),
host_set_members as (
    select string_agg(distinct host_id, '|') as host_ids,
           set_id            
      from host_plugin_set_member
     where set_id in (select public_id from host_sets)
  group by set_id
), 
final as (
           select hs.public_id,
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
                  ppe.preferred_endpoints,
                  hsm.host_ids
             from host_sets hs
             join host_catalog hc         on hc.public_id = hs.catalog_id
  left outer join preferred_endpoints ppe on ppe.host_set_id = hs.public_id
  left outer join host_set_members hsm    on hsm.set_id = hs.public_id
)
  select *  
    from final
order by update_time desc, public_id desc;
`
)
