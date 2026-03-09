// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

const (
	credStaticUsernamePasswordRewrapQuery = `
select distinct userpass.public_id,
                userpass.password_encrypted,
                userpass.key_id
           from credential_static_username_password_credential userpass
     inner join credential_static_store store
             on store.public_id = userpass.store_id
          where store.project_id = ?
            and userpass.key_id = ?;
`

	credStaticUsernamePasswordDomainRewrapQuery = `
select distinct upd.public_id,
                upd.password_encrypted,
                upd.key_id
           from credential_static_username_password_domain_credential upd
     inner join credential_static_store store
             on store.public_id = upd.store_id
          where store.project_id = ?
            and upd.key_id = ?;
`

	credStaticPasswordRewrapQuery = `
select distinct pass.public_id,
                pass.password_encrypted,
                pass.key_id
           from credential_static_password_credential pass
     inner join credential_static_store store
             on store.public_id = pass.store_id
          where store.project_id = ?
            and pass.key_id = ?;
`
	credStaticSshPrivKeyRewrapQuery = `
select distinct ssh.public_id,
                ssh.private_key_encrypted,
                ssh.private_key_passphrase_encrypted,
                ssh.key_id
           from credential_static_ssh_private_key_credential ssh
     inner join credential_static_store store
             on store.public_id = ssh.store_id
          where store.project_id = ?
            and ssh.key_id = ?;
`

	credStaticJsonRewrapQuery = `
select distinct json.public_id,
                json.object_encrypted,
                json.key_id
           from credential_static_json_credential json
     inner join credential_static_store store
             on store.public_id = json.store_id
          where store.project_id = ?
            and json.key_id = ?;
`

	estimateCountCredentials = `
select sum(reltuples::bigint) as estimate
  from pg_class
 where oid in (
  'credential_static_json_credential'::regclass,
  'credential_static_username_password_credential'::regclass,
  'credential_static_username_password_domain_credential'::regclass,
  'credential_static_password_credential'::regclass,
  'credential_static_ssh_private_key_credential'::regclass
 )
`

	listCredentialsTemplate = `
with credentials as (
    select public_id
      from credential_static
     where store_id = @store_id
  order by create_time desc, public_id desc
     limit %d
),
json_creds as (
  select *
    from credential_static_json_credential
   where public_id in (select public_id from credentials)
),
upw_creds as (
  select *
    from credential_static_username_password_credential
   where public_id in (select public_id from credentials)
),
upd_creds as (
  select * 
    from credential_static_username_password_domain_credential
  where public_id in (select public_id from credentials)
),
p_creds as (
  select * 
    from credential_static_password_credential
  where public_id in (select public_id from credentials)
),
ssh_creds as (
  select *
    from credential_static_ssh_private_key_credential
   where public_id in (select public_id from credentials)
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
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         object_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'json' as type
    from json_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upw' as type
    from upw_creds
    union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         domain,
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upd' as type
    from upd_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'p' as type
    from p_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         private_key_hmac as hmac1,
         private_key_passphrase_hmac as hmac2,
         'ssh' as type
    from ssh_creds
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listCredentialsPageTemplate = `
with credentials as (
    select public_id
      from credential_static
     where store_id = @store_id
       and (create_time, public_id) < (@last_item_create_time, @last_item_id)
  order by create_time desc, public_id desc
     limit %d
),
json_creds as (
  select *
    from credential_static_json_credential
   where public_id in (select public_id from credentials)
),
upw_creds as (
  select *
    from credential_static_username_password_credential
   where public_id in (select public_id from credentials)
),
upd_creds as (
  select *
    from credential_static_username_password_domain_credential
   where public_id in (select public_id from credentials)
),
p_creds as (
  select *
    from credential_static_password_credential
   where public_id in (select public_id from credentials)
),
ssh_creds as (
  select *
    from credential_static_ssh_private_key_credential
   where public_id in (select public_id from credentials)
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
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         object_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'json' as type
    from json_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upw' as type
    from upw_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         domain,
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upd' as type
    from upd_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'p' as type
    from p_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         private_key_hmac as hmac1,
         private_key_passphrase_hmac as hmac2,
         'ssh' as type
    from ssh_creds
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listCredentialsRefreshTemplate = `
with credentials as (
    select public_id
      from credential_static
     where store_id = @store_id
       and update_time > @updated_after_time
  order by update_time desc, public_id desc
     limit %d
),
json_creds as (
  select *
    from credential_static_json_credential
   where public_id in (select public_id from credentials)
),
upw_creds as (
  select *
    from credential_static_username_password_credential
   where public_id in (select public_id from credentials)
),
upd_creds as (
  select *
    from credential_static_username_password_domain_credential
   where public_id in (select public_id from credentials)
),
p_creds as (
  select * 
    from credential_static_password_credential
  where public_id in (select public_id from credentials)
),
ssh_creds as (
  select *
    from credential_static_ssh_private_key_credential
   where public_id in (select public_id from credentials)
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
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         object_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'json' as type
    from json_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upw' as type
    from upw_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         domain,
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upd' as type
    from upd_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'p' as type
    from p_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         private_key_hmac as hmac1,
         private_key_passphrase_hmac as hmac2,
         'ssh' as type
    from ssh_creds
)
  select *
    from final
order by update_time desc, public_id desc;
`

	listCredentialsRefreshPageTemplate = `
with credentials as (
    select public_id
      from credential_static
     where store_id = @store_id
       and update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
  order by update_time desc, public_id desc
     limit %d
),
json_creds as (
  select *
    from credential_static_json_credential
   where public_id in (select public_id from credentials)
),
upw_creds as (
  select *
    from credential_static_username_password_credential
   where public_id in (select public_id from credentials)
),
upd_creds as (
  select *
    from credential_static_username_password_domain_credential
   where public_id in (select public_id from credentials)
),
p_creds as (
  select * 
    from credential_static_password_credential
  where public_id in (select public_id from credentials)
),
ssh_creds as (
  select *
    from credential_static_ssh_private_key_credential
   where public_id in (select public_id from credentials)
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
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         object_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'json' as type
    from json_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upw' as type
    from upw_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         domain,
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'upd' as type
    from upd_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         null as username,     -- Add this to make the union uniform
         null as domain,       -- Add this to make the union uniform
         key_id,
         password_hmac as hmac1,
         null::bytea as hmac2, -- Add this to make the union uniform
         'p' as type
    from p_creds
   union
  select public_id,
         store_id,
         project_id,
         name,
         description,
         create_time,
         update_time,
         version,
         username,
         null as domain,       -- Add this to make the union uniform
         key_id,
         private_key_hmac as hmac1,
         private_key_passphrase_hmac as hmac2,
         'ssh' as type
    from ssh_creds
)
  select *
    from final
order by update_time desc, public_id desc;
`
)
