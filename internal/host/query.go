// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

const (
	estimateCountCatalogsQuery = `
select sum(reltuples::bigint) as estimate from pg_class where oid in (
	'static_host_catalog'::regclass,
	'host_plugin_catalog'::regclass
)
`

	listDeletedIdsQuery = `
select public_id
  from static_host_catalog_deleted
 where delete_time >= @since
 union
select public_id
  from host_plugin_catalog_deleted
 where delete_time >= @since
`

	listCatalogsTemplate = `
with catalogs as (
    select public_id
      from host_catalog
     where %s -- search condition for project IDs is constructed
  order by create_time desc, public_id desc
     limit %d
),
plugin_catalogs as (
  select public_id,
         project_id,
         plugin_id,
         name,
         description,
         create_time,
         update_time,
         version,
         attributes,
         secrets_hmac,
         worker_filter
    from host_plugin_catalog
   where public_id in (select public_id from catalogs)
),
static_catalogs as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version
    from static_host_catalog
   where public_id in (select public_id from catalogs)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         plugin_id,
         attributes,
         secrets_hmac,
         worker_filter,
         'plugin' as subtype
    from plugin_catalogs
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as plugin_id,   -- Add to make union uniform
         null as attributes,  -- Add to make union uniform
         null as secrets_hmac, -- Add to make union uniform
         null as worker_filter, -- Add to make union uniform
         'static' as subtype
    from static_catalogs
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listCatalogsPageTemplate = `
with catalogs as (
    select public_id
      from host_catalog
     where %s -- search condition for project IDs is constructed
       and (create_time, public_id) < (@last_item_create_time, @last_item_id)
  order by create_time desc, public_id desc
     limit %d
),
plugin_catalogs as (
  select public_id,
         project_id,
         plugin_id,
         name,
         description,
         create_time,
         update_time,
         version,
         attributes,
         secrets_hmac,
         worker_filter
    from host_plugin_catalog
   where public_id in (select public_id from catalogs)
),
static_catalogs as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version
    from static_host_catalog
   where public_id in (select public_id from catalogs)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         plugin_id,
         attributes,
         secrets_hmac,
         worker_filter,
         'plugin' as subtype
    from plugin_catalogs
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as plugin_id,   -- Add to make union uniform
         null as attributes,  -- Add to make union uniform
         null as secrets_hmac, -- Add to make union uniform
         null as worker_filter, -- Add to make union uniform
         'static' as subtype
    from static_catalogs
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listCatalogsRefreshTemplate = `
with catalogs as (
    select public_id
      from host_catalog
     where %s -- search condition for project IDs is constructed
       and update_time > @updated_after_time
  order by update_time desc, public_id desc
     limit %d
),
plugin_catalogs as (
  select public_id,
         project_id,
         plugin_id,
         name,
         description,
         create_time,
         update_time,
         version,
         attributes,
         secrets_hmac,
         worker_filter
    from host_plugin_catalog
   where public_id in (select public_id from catalogs)
),
static_catalogs as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version
    from static_host_catalog
   where public_id in (select public_id from catalogs)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         plugin_id,
         attributes,
         secrets_hmac,
         worker_filter,
         'plugin' as subtype
    from plugin_catalogs
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as plugin_id,   -- Add to make union uniform
         null as attributes,  -- Add to make union uniform
         null as secrets_hmac, -- Add to make union uniform
         null as worker_filter, -- Add to make union uniform
         'static' as subtype
    from static_catalogs
)
  select *
    from final
order by update_time desc, public_id desc;
`

	listCatalogsRefreshPageTemplate = `
with catalogs as (
    select public_id
      from host_catalog
     where %s -- search condition for project IDs is constructed
       and update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
  order by update_time desc, public_id desc
     limit %d
),
plugin_catalogs as (
  select public_id,
         project_id,
         plugin_id,
         name,
         description,
         create_time,
         update_time,
         version,
         attributes,
         secrets_hmac,
         worker_filter
    from host_plugin_catalog
   where public_id in (select public_id from catalogs)
),
static_catalogs as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version
    from static_host_catalog
   where public_id in (select public_id from catalogs)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         plugin_id,
         attributes,
         secrets_hmac,
         worker_filter,
         'plugin' as subtype
    from plugin_catalogs
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as plugin_id,   -- Add to make union uniform
         null as attributes,  -- Add to make union uniform
         null as secrets_hmac, -- Add to make union uniform
         null as worker_filter, -- Add to make union uniform
         'static' as subtype
    from static_catalogs
)
  select *
    from final
order by update_time desc, public_id desc;
`
)
