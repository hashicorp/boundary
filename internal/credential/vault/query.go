// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

const (
	insertTokenQuery = `
insert into credential_vault_token (
  token_hmac, -- $1
  token, -- $2
  store_id, -- $3
  key_id, -- $4
  status, -- $5
  last_renewal_time, -- $6
  expiration_time -- $7
) values (
  @1, -- token_hmac
  @2, -- token
  @3, -- store_id
  @4, -- key_id
  @5, -- status
  @6, -- last_renewal_time
  wt_add_seconds_to_now(@7)  -- expiration_time
);
`

	insertCredentialWithExpirationQuery = `
insert into credential_vault_credential (
  public_id, -- $1
  library_id, -- $2
  session_id, -- $3
  token_hmac, -- $4
  external_id, -- $5
  is_renewable, -- $6
  status, -- $7
  last_renewal_time, -- $8
  expiration_time -- $9
) values (
  @public_id, -- public_id
  @library_id, -- library_id
  @session_id, -- session_id
  @token_hmac, -- token_hmac
  @external_id, -- external_id
  @is_renewable, -- is_renewable
  @status, -- status
  @last_renewal_time, -- last_renewal_time
  wt_add_seconds_to_now(@expiration_time)  -- expiration_time
);
`

	insertCredentialWithInfiniteExpirationQuery = `
insert into credential_vault_credential (
  public_id, -- $1
  library_id, -- $2
  session_id, -- $3
  token_hmac, -- $4
  external_id, -- $5
  is_renewable, -- $6
  status, -- $7
  last_renewal_time, -- $8
  expiration_time -- infinity
) values (
  @public_id, -- public_id
  @library_id, -- library_id
  @session_id, -- session_id
  @token_hmac, -- token_hmac
  @external_id, -- external_id
  @is_renewable, -- is_renewable
  @status, -- status
  @last_renewal_time, -- last_renewal_time
  'infinity' -- expiration_time
);
`

	upsertClientCertQuery = `
insert into credential_vault_client_certificate
  (store_id, certificate, certificate_key, certificate_key_hmac, key_id)
values
  (@store_id, @certificate, @certificate_key, @certificate_key_hmac, @key_id)
on conflict (store_id) do update
  set certificate          = excluded.certificate,
      certificate_key      = excluded.certificate_key,
      certificate_key_hmac = excluded.certificate_key_hmac,
      key_id               = excluded.key_id
returning *;
`

	deleteClientCertQuery = `
delete from credential_vault_client_certificate
 where store_id = ?;
`

	selectLibrariesQuery = `
select *
  from credential_vault_library_issue_credentials
 where public_id in (%s);
`

	updateSessionCredentialQuery = `
update session_credential_dynamic
   set credential_id = @public_id
 where library_id = @library_id
   and session_id = @session_id
   and credential_purpose = @purpose
   and credential_id is null
returning *;
`

	updateTokenExpirationQuery = `
update credential_vault_token
   set last_renewal_time = now(),
       expiration_time   = wt_add_seconds_to_now(?)
 where token_hmac = ?;
`

	updateTokenStatusQuery = `
update credential_vault_token
   set status = ?
 where token_hmac = ?;
`

	tokenRenewalNextRunInQuery = `
select extract(epoch from (last_renewal_time + (expiration_time - last_renewal_time) / 2) - now())::int as renewal_in
  from credential_vault_token
 where expiration_time = (
         select min(expiration_time)
           from credential_vault_token
          where status in ('current', 'maintaining')
       );
`

	revokeCredentialsQuery = `
update credential_vault_credential
   set status = 'revoke'
 where session_id = ?
   and status = 'active';
`

	updateCredentialStatusByTokenQuery = `
update credential_vault_credential
   set status = ?
 where token_hmac = ?;
`

	credentialRenewalNextRunInQuery = `
select
	extract(epoch from (renewal_time - now()))::int as renewal_in
  	from credential_vault_credential_private
 	where expiration_time = (
	  select min(expiration_time)
  	    from credential_vault_credential_private
       where status = 'active'
	);
`

	updateCredentialExpirationQuery = `
update credential_vault_credential
   set last_renewal_time = now(),
       expiration_time   = wt_add_seconds_to_now(?)
 where public_id = ?;
`

	updateCredentialStatusQuery = `
update credential_vault_credential
   set status = ?
 where public_id = ?;
`

	softDeleteStoreQuery = `
update credential_vault_store
   set delete_time = now()
 where public_id = ?
   and delete_time is null
returning *;
`

	credStoreCleanupWhereClause = `
delete_time is not null
   and public_id not in 
   (
     select store_id from credential_vault_token
      where status = ?
        and expiration_time > now()
   )
`

	credCleanupQuery = `
delete from credential_vault_credential 
 where session_id is null
   and status not in ('active', 'revoke')
`

	estimateCountCredentialLibraries = `
select sum(reltuples::bigint) as estimate
  from pg_class
 where oid in (
  'credential_vault_generic_library'::regclass,
  'credential_vault_ssh_cert_library'::regclass,
  'credential_vault_ldap_library'::regclass
)
`

	listLibrariesTemplate = `
with libraries as (
    select public_id
      from credential_library
     where store_id = @store_id
  order by create_time desc, public_id desc
     limit %d
),
generic_libs as (
  select *
    from credential_vault_generic_library
   where public_id in (select public_id from libraries)
),
ssh_cert_libs as (
  select *
    from credential_vault_ssh_cert_library
   where public_id in (select public_id from libraries)
),
ldap_libs as (
  select *
    from credential_vault_ldap_library
   where public_id in (select public_id from libraries)
),
final as (
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         http_method,
         http_request_body,
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'generic' as type
    from generic_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,       -- Add to make union uniform
         null as http_request_body, -- Add to make union uniform
         username,
         key_type,
         key_bits,
         ttl,
         key_id,
         critical_options,
         extensions,
         additional_valid_principals,
         'ssh' as type
    from ssh_cert_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,                  -- Add to make union uniform
         null as http_request_body,            -- Add to make union uniform
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'ldap' as type
    from ldap_libs
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listLibrariesPageTemplate = `
with libraries as (
    select public_id
      from credential_library
     where store_id = @store_id
       and (create_time, public_id) < (@last_item_create_time, @last_item_id)
  order by create_time desc, public_id desc
     limit %d
),
generic_libs as (
  select *
    from credential_vault_generic_library
   where public_id in (select public_id from libraries)
),
ssh_cert_libs as (
  select *
    from credential_vault_ssh_cert_library
   where public_id in (select public_id from libraries)
),
ldap_libs as (
  select *
    from credential_vault_ldap_library
   where public_id in (select public_id from libraries)
),
final as (
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         http_method,
         http_request_body,
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'generic' as type
    from generic_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,       -- Add to make union uniform
         null as http_request_body, -- Add to make union uniform
         username,
         key_type,
         key_bits,
         ttl,
         key_id,
         critical_options,
         extensions,
         additional_valid_principals,
         'ssh' as type
    from ssh_cert_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,                  -- Add to make union uniform
         null as http_request_body,            -- Add to make union uniform
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'ldap' as type
    from ldap_libs
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listLibrariesRefreshTemplate = `
with libraries as (
    select public_id
      from credential_library
     where store_id = @store_id
       and update_time > @updated_after_time
  order by update_time desc, public_id desc
     limit %d
),
generic_libs as (
  select *
    from credential_vault_generic_library
   where public_id in (select public_id from libraries)
),
ssh_cert_libs as (
  select *
    from credential_vault_ssh_cert_library
   where public_id in (select public_id from libraries)
),
ldap_libs as (
  select *
    from credential_vault_ldap_library
   where public_id in (select public_id from libraries)
),
final as (
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         http_method,
         http_request_body,
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'generic' as type
    from generic_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,       -- Add to make union uniform
         null as http_request_body, -- Add to make union uniform
         username,
         key_type,
         key_bits,
         ttl,
         key_id,
         critical_options,
         extensions,
         additional_valid_principals,
         'ssh' as type
    from ssh_cert_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,                  -- Add to make union uniform
         null as http_request_body,            -- Add to make union uniform
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'ldap' as type
    from ldap_libs
)
  select *
    from final
order by update_time desc, public_id desc;
`

	listLibrariesRefreshPageTemplate = `
with libraries as (
    select public_id
      from credential_library
     where store_id = @store_id
       and update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
  order by update_time desc, public_id desc
     limit %d
),
generic_libs as (
  select *
    from credential_vault_generic_library
   where public_id in (select public_id from libraries)
),
ssh_cert_libs as (
  select *
    from credential_vault_ssh_cert_library
   where public_id in (select public_id from libraries)
),
ldap_libs as (
  select *
    from credential_vault_ldap_library
   where public_id in (select public_id from libraries)
),
final as (
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         http_method,
         http_request_body,
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'generic' as type
    from generic_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,       -- Add to make union uniform
         null as http_request_body, -- Add to make union uniform
         username,
         key_type,
         key_bits,
         ttl,
         key_id,
         critical_options,
         extensions,
         additional_valid_principals,
         'ssh' as type
    from ssh_cert_libs
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         vault_path,
         credential_type,
         null as http_method,                  -- Add to make union uniform
         null as http_request_body,            -- Add to make union uniform
         null as username,                     -- Add to make union uniform
         null as key_type,                     -- Add to make union uniform
         null as key_bits,                     -- Add to make union uniform
         null as ttl,                          -- Add to make union uniform
         null as key_id,                       -- Add to make union uniform
         null as critical_options,             -- Add to make union uniform
         null as extensions,                   -- Add to make union uniform
         null as additional_valid_principals,  -- Add to make union uniform
         'ldap' as type
    from ldap_libs
)
  select *
    from final
order by update_time desc, public_id desc;
`
)
