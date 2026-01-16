// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

const (
	setChangesQuery = `
with
final_hosts (host_id) as (
  -- returns the SET list
  select public_id
    from static_host
   where public_id in (%s)
),
current_hosts (host_id) as (
  -- returns the current list
  select host_id
    from static_host_set_member
   where set_id = @1 -- this trailing space is needed by gorm
),
keep_hosts (host_id) as (
  -- returns the KEEP list
  select host_id
    from current_hosts
   where host_id in (select * from final_hosts)
),
delete_hosts (host_id) as (
  -- returns the DELETE list
  select host_id
    from current_hosts
   where host_id not in (select * from final_hosts)
),
insert_hosts (host_id) as (
  -- returns the ADD list
  select host_id
    from final_hosts
   where host_id not in (select * from keep_hosts)
),
final (action, host_id) as (
  select 'delete', host_id
    from delete_hosts
   union
  select 'add', host_id
    from insert_hosts
)
select * from final
order by action, host_id;
`

	estimateCountHosts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('static_host'::regclass)
`

	listHostsTemplate = `
with hosts as (
    select public_id,
           create_time,
           update_time,
           name,
           description,
           catalog_id,
           address,
           version
      from static_host
     where catalog_id = @catalog_id
  order by create_time desc, public_id desc
     limit %d
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from static_host_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
                  h.create_time,
                  h.update_time,
                  h.name,
                  h.description,
                  h.catalog_id,
                  h.address,
                  h.version,
                  hsi.set_ids
             from hosts h
  left outer join host_set_ids hsi on hsi.host_id = h.public_id
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listHostsPageTemplate = `
with hosts as (
    select public_id,
           create_time,
           update_time,
           name,
           description,
           catalog_id,
           address,
           version
      from static_host
     where catalog_id = @catalog_id
       and (create_time, public_id) < (@last_item_create_time, @last_item_id)
  order by create_time desc, public_id desc
     limit %d
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from static_host_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
                  h.create_time,
                  h.update_time,
                  h.name,
                  h.description,
                  h.catalog_id,
                  h.address,
                  h.version,
                  hsi.set_ids
             from hosts h
  left outer join host_set_ids hsi on hsi.host_id = h.public_id
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listHostsRefreshTemplate = `
with hosts as (
    select public_id,
           create_time,
           update_time,
           name,
           description,
           catalog_id,
           address,
           version
      from static_host
     where catalog_id = @catalog_id
       and update_time > @updated_after_time
  order by update_time desc, public_id desc
     limit %d
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from static_host_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
                  h.create_time,
                  h.update_time,
                  h.name,
                  h.description,
                  h.catalog_id,
                  h.address,
                  h.version,
                  hsi.set_ids
             from hosts h
  left outer join host_set_ids hsi on hsi.host_id = h.public_id
)
  select *
    from final
order by update_time desc, public_id desc;
`
	listHostsRefreshPageTemplate = `
with hosts as (
    select public_id,
           create_time,
           update_time,
           name,
           description,
           catalog_id,
           address,
           version
      from static_host
     where catalog_id = @catalog_id
       and update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
  order by update_time desc, public_id desc
     limit %d
),
host_set_ids as (
    select string_agg(distinct set_id, '|') as set_ids,
           host_id
      from static_host_set_member
     where host_id in (select public_id from hosts)
  group by host_id
),
final as (
           select h.public_id,
                  h.create_time,
                  h.update_time,
                  h.name,
                  h.description,
                  h.catalog_id,
                  h.address,
                  h.version,
                  hsi.set_ids
             from hosts h
  left outer join host_set_ids hsi on hsi.host_id = h.public_id
)
  select *
    from final
order by update_time desc, public_id desc;
`

	estimateCountHostSets = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('static_host_set'::regclass)
`
)
