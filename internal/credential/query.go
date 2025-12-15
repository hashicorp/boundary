// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

const (
	estimateCountStoresQuery = `
select sum(reltuples::bigint) as estimate from pg_class where oid in (
	'credential_vault_store'::regclass,
	'credential_static_store'::regclass
)
`

	listDeletedIdsQuery = `
select public_id
  from credential_vault_store_deleted
 where delete_time >= @since
 union
select public_id
  from credential_static_store_deleted
 where delete_time >= @since
`

	listStoresTemplate = `
with stores as (
    select public_id
      from credential_store
     where %s -- search condition for project IDs is constructed
  order by create_time desc, public_id desc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
     and delete_time is null
),
vault_tokens as (
  select store_id,
         token_hmac,
         status
    from credential_vault_token
   where store_id in (select public_id from stores)
     and status = 'current'
),
vault_client_certs as (
  select store_id,
         certificate,
         certificate_key_hmac
    from credential_vault_client_certificate
   where store_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
     select store.public_id,
            store.project_id,
            store.name,
            store.description,
            store.create_time,
            store.update_time,
            store.version,
            store.delete_time,
            store.vault_address,
            store.namespace,
            store.ca_cert,
            store.tls_server_name,
            store.tls_skip_verify,
            store.worker_filter,
            token.token_hmac                  as token_hmac,
            coalesce(token.status, 'expired') as token_status,
            cert.certificate                  as client_cert,
            cert.certificate_key_hmac         as client_cert_key_hmac,
            'vault' as subtype
       from vault_stores store
  left join vault_tokens token      on store.public_id = token.store_id
  left join vault_client_certs cert on store.public_id = cert.store_id
      union
     select public_id,
            project_id,
            name,
            description,
            create_time,
            update_time,
            version,
            null as delete_time,          -- Add to make union uniform
            null as vault_address,        -- Add to make union uniform
            null as namespace,            -- Add to make union uniform
            null as ca_cert,              -- Add to make union uniform
            null as tls_server_name,      -- Add to make union uniform
            null as tls_skip_verify,      -- Add to make union uniform
            null as worker_filter,        -- Add to make union uniform
            null as token_hmac,           -- Add to make union uniform
            null as token_status,         -- Add to make union uniform
            null as client_cert,          -- Add to make union uniform
            null as client_cert_key_hmac, -- Add to make union uniform
            'static' as subtype
       from static_stores
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listStoresPageTemplate = `
with stores as (
    select public_id
      from credential_store
     where (create_time, public_id) < (@last_item_create_time, @last_item_id) and
           %s -- search condition for project IDs is constructed
  order by create_time desc, public_id desc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
     and delete_time is null
),
vault_tokens as (
  select store_id,
         token_hmac,
         status
    from credential_vault_token
   where store_id in (select public_id from stores)
     and status = 'current'
),
vault_client_certs as (
  select store_id,
         certificate,
         certificate_key_hmac
    from credential_vault_client_certificate
   where store_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
     select store.public_id,
            store.project_id,
            store.name,
            store.description,
            store.create_time,
            store.update_time,
            store.version,
            store.delete_time,
            store.vault_address,
            store.namespace,
            store.ca_cert,
            store.tls_server_name,
            store.tls_skip_verify,
            store.worker_filter,
            token.token_hmac                  as token_hmac,
            coalesce(token.status, 'expired') as token_status,
            cert.certificate                  as client_cert,
            cert.certificate_key_hmac         as client_cert_key_hmac,
            'vault' as subtype
       from vault_stores store
  left join vault_tokens token      on store.public_id = token.store_id
  left join vault_client_certs cert on store.public_id = cert.store_id
      union
     select public_id,
            project_id,
            name,
            description,
            create_time,
            update_time,
            version,
            null as delete_time,          -- Add to make union uniform
            null as vault_address,        -- Add to make union uniform
            null as namespace,            -- Add to make union uniform
            null as ca_cert,              -- Add to make union uniform
            null as tls_server_name,      -- Add to make union uniform
            null as tls_skip_verify,      -- Add to make union uniform
            null as worker_filter,        -- Add to make union uniform
            null as token_hmac,           -- Add to make union uniform
            null as token_status,         -- Add to make union uniform
            null as client_cert,          -- Add to make union uniform
            null as client_cert_key_hmac, -- Add to make union uniform
            'static' as subtype
       from static_stores
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listStoresRefreshTemplate = `
with stores as (
    select public_id
      from credential_store
     where update_time > @updated_after_time and
           %s -- search condition for project IDs is constructed
  order by update_time desc, public_id desc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
     and delete_time is null
),
vault_tokens as (
  select store_id,
         token_hmac,
         status
    from credential_vault_token
   where store_id in (select public_id from stores)
     and status = 'current'
),
vault_client_certs as (
  select store_id,
         certificate,
         certificate_key_hmac
    from credential_vault_client_certificate
   where store_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
     select store.public_id,
            store.project_id,
            store.name,
            store.description,
            store.create_time,
            store.update_time,
            store.version,
            store.delete_time,
            store.vault_address,
            store.namespace,
            store.ca_cert,
            store.tls_server_name,
            store.tls_skip_verify,
            store.worker_filter,
            token.token_hmac                  as token_hmac,
            coalesce(token.status, 'expired') as token_status,
            cert.certificate                  as client_cert,
            cert.certificate_key_hmac         as client_cert_key_hmac,
            'vault' as subtype
       from vault_stores store
  left join vault_tokens token      on store.public_id = token.store_id
  left join vault_client_certs cert on store.public_id = cert.store_id
      union
     select public_id,
            project_id,
            name,
            description,
            create_time,
            update_time,
            version,
            null as delete_time,          -- Add to make union uniform
            null as vault_address,        -- Add to make union uniform
            null as namespace,            -- Add to make union uniform
            null as ca_cert,              -- Add to make union uniform
            null as tls_server_name,      -- Add to make union uniform
            null as tls_skip_verify,      -- Add to make union uniform
            null as worker_filter,        -- Add to make union uniform
            null as token_hmac,           -- Add to make union uniform
            null as token_status,         -- Add to make union uniform
            null as client_cert,          -- Add to make union uniform
            null as client_cert_key_hmac, -- Add to make union uniform
            'static' as subtype
       from static_stores
)
  select *
    from final
order by update_time desc, public_id desc;
`

	listStoresRefreshPageTemplate = `
with stores as (
    select public_id
      from credential_store
     where update_time > @updated_after_time and
           (update_time, public_id) < (@last_item_update_time, @last_item_id) and
           %s -- search condition for project IDs is constructed
  order by update_time desc, public_id desc
     limit %d
),
vault_stores as (
  select *
    from credential_vault_store
   where public_id in (select public_id from stores)
     and delete_time is null
),
vault_tokens as (
  select store_id,
         token_hmac,
         status
    from credential_vault_token
   where store_id in (select public_id from stores)
     and status = 'current'
),
vault_client_certs as (
  select store_id,
         certificate,
         certificate_key_hmac
    from credential_vault_client_certificate
   where store_id in (select public_id from stores)
),
static_stores as (
  select *
    from credential_static_store
   where public_id in (select public_id from stores)
),
final as (
     select store.public_id,
            store.project_id,
            store.name,
            store.description,
            store.create_time,
            store.update_time,
            store.version,
            store.delete_time,
            store.vault_address,
            store.namespace,
            store.ca_cert,
            store.tls_server_name,
            store.tls_skip_verify,
            store.worker_filter,
            token.token_hmac                  as token_hmac,
            coalesce(token.status, 'expired') as token_status,
            cert.certificate                  as client_cert,
            cert.certificate_key_hmac         as client_cert_key_hmac,
            'vault' as subtype
       from vault_stores store
  left join vault_tokens token      on store.public_id = token.store_id
  left join vault_client_certs cert on store.public_id = cert.store_id
      union
     select public_id,
            project_id,
            name,
            description,
            create_time,
            update_time,
            version,
            null as delete_time,          -- Add to make union uniform
            null as vault_address,        -- Add to make union uniform
            null as namespace,            -- Add to make union uniform
            null as ca_cert,              -- Add to make union uniform
            null as tls_server_name,      -- Add to make union uniform
            null as tls_skip_verify,      -- Add to make union uniform
            null as worker_filter,        -- Add to make union uniform
            null as token_hmac,           -- Add to make union uniform
            null as token_status,         -- Add to make union uniform
            null as client_cert,          -- Add to make union uniform
            null as client_cert_key_hmac, -- Add to make union uniform
            'static' as subtype
       from static_stores
)
  select *
    from final
order by update_time desc, public_id desc;
`
)
