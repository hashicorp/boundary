// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

const (
	estimateCountStores = `
select sum(reltuples::bigint) as estimate from pg_class where oid in (
	'credential_vault_store'::regclass,
	'credential_static_store'::regclass
)
`

	/*
	   select store.public_id                   as public_id,
	           store.project_id                  as project_id,
	           store.name                        as name,
	           store.description                 as description,
	           store.create_time                 as create_time,
	           store.update_time                 as update_time,
	           store.delete_time                 as delete_time,
	           store.version                     as version,
	           store.vault_address               as vault_address,
	           store.namespace                   as namespace,
	           store.ca_cert                     as ca_cert,
	           store.tls_server_name             as tls_server_name,
	           store.tls_skip_verify             as tls_skip_verify,
	           store.worker_filter               as worker_filter,
	           token.token_hmac                  as token_hmac,
	           coalesce(token.status, 'expired') as token_status,
	           cert.certificate                  as client_cert,
	           cert.certificate_key_hmac         as client_cert_key_hmac
	      from credential_vault_store store
	      left join credential_vault_token token
	        on store.public_id = token.store_id
	       and token.status = 'current'
	      left join credential_vault_client_certificate cert
	        on store.public_id = cert.store_id
	     where store.delete_time is null;
	*/

	listStoresTemplate = `
with stores as (
    select public_id
      from credential_store
     where %s -- search condition for project IDs is constructed
  order by create_time desc, public_id asc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         delete_time,
         vault_address,
         namespace,
         ca_cert,
         tls_server_name,
         tls_skip_verify,
         worker_filter,
         'vault' as subtype
    from vault_stores
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as delete_time,     -- Add to make union uniform
         null as vault_address,   -- Add to make union uniform
         null as namespace,       -- Add to make union uniform
         null as ca_cert,         -- Add to make union uniform
         null as tls_server_name, -- Add to make union uniform
         null as tls_skip_verify, -- Add to make union uniform
         null as worker_filter,   -- Add to make union uniform
         'static' as subtype
    from static_stores
)
  select *
    from final
order by create_time desc, public_id asc;
`

	listStoresPageTemplate = `
with stores as (
    select public_id
      from credential_store
     where (create_time, public_id) < (@last_item_create_time, @last_item_id) and
           %s -- search condition for project IDs is constructed
  order by create_time desc, public_id asc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         delete_time,
         vault_address,
         namespace,
         ca_cert,
         tls_server_name,
         tls_skip_verify,
         worker_filter,
         'vault' as subtype
    from vault_stores
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as delete_time,     -- Add to make union uniform
         null as vault_address,   -- Add to make union uniform
         null as namespace,       -- Add to make union uniform
         null as ca_cert,         -- Add to make union uniform
         null as tls_server_name, -- Add to make union uniform
         null as tls_skip_verify, -- Add to make union uniform
         null as worker_filter,   -- Add to make union uniform
         'static' as subtype
    from static_stores
)
  select *
    from final
order by create_time desc, public_id asc;
`

	listStoresRefreshTemplate = `
with stores as (
    select public_id
      from credential_store
     where update_time > @updated_after_time and
           %s -- search condition for project IDs is constructed
  order by update_time desc, public_id asc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         delete_time,
         vault_address,
         namespace,
         ca_cert,
         tls_server_name,
         tls_skip_verify,
         worker_filter,
         'vault' as subtype
    from vault_stores
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as delete_time,     -- Add to make union uniform
         null as vault_address,   -- Add to make union uniform
         null as namespace,       -- Add to make union uniform
         null as ca_cert,         -- Add to make union uniform
         null as tls_server_name, -- Add to make union uniform
         null as tls_skip_verify, -- Add to make union uniform
         null as worker_filter,   -- Add to make union uniform
         'static' as subtype
    from static_stores
)
  select *
    from final
order by update_time desc, public_id asc;
`

	listStoresRefreshPageTemplate = `
with stores as (
    select public_id
      from credential_store
     where update_time > @updated_after_time and
           (update_time, public_id) < (@last_item_update_time, @last_item_id) and
           %s -- search condition for project IDs is constructed
  order by update_time desc, public_id asc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         delete_time,
         vault_address,
         namespace,
         ca_cert,
         tls_server_name,
         tls_skip_verify,
         worker_filter,
         'vault' as subtype
    from vault_stores
   union
  select public_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as delete_time,     -- Add to make union uniform
         null as vault_address,   -- Add to make union uniform
         null as namespace,       -- Add to make union uniform
         null as ca_cert,         -- Add to make union uniform
         null as tls_server_name, -- Add to make union uniform
         null as tls_skip_verify, -- Add to make union uniform
         null as worker_filter,   -- Add to make union uniform
         'static' as subtype
    from static_stores
)
  select *
    from final
order by update_time desc, public_id asc;
`
)
