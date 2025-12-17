// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

const (
	estimateCountAuthMethodsQuery = `
select sum(reltuples::bigint) as estimate from pg_class where oid in (
    'auth_password_method'::regclass,
    'auth_ldap_method'::regclass,
    'auth_oidc_method'::regclass
)
`

	listDeletedIdsQuery = `
select public_id
  from auth_password_method_deleted
 where delete_time >= @since
 union
select public_id
  from auth_oidc_method_deleted
 where delete_time >= @since
 union
select public_id
  from auth_ldap_method_deleted
 where delete_time >= @since
`

	listAuthMethodsTemplate = `
with auth_methods as (
    select public_id
      from auth_method
     where %s -- search condition for scope IDs is constructed
  order by create_time desc, public_id desc
     limit %d
),
ldap as (
    select *
      from ldap_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
oidc as (
    select *
      from oidc_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
password as (
    select *
      from auth_password_method_with_is_primary
     where public_id in (select public_id from auth_methods)
),
final as (
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           start_tls,
           insecure_tls,
           discover_dn,
           anon_group_search,
           upn_domain,
           enable_groups,
           use_token_groups,
           maximum_page_size,
           urls,
           certs,
           account_attribute_map,
           user_dn,
           user_attr,
           user_filter,
           group_dn,
           group_attr,
           group_filter,
           client_certificate_key,
           client_certificate_key_hmac,
           client_certificate_key_id,
           client_certificate_cert,
           bind_dn,
           bind_password,
           bind_password_hmac,
           bind_password_key_id,
           dereference_aliases,
           null as disable_discovered_config_validation, -- Add to make union uniform
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'ldap' as subtype
      from ldap
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           null as start_tls,                    -- Add to make union uniform
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           disable_discovered_config_validation,
           api_url,
           issuer,
           client_id,
           client_secret,
           client_secret_hmac,
           key_id,
           max_age,
           algs,
           auds,
           certs,
           claims_scopes,
           prompts,
           account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'oidc' as subtype
      from oidc
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           null as state,                        -- Add to make union uniform
           null as start_tls,
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           null as disable_discovered_config_validation,
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           password_conf_id,
           min_login_name_length,
           min_password_length,
           'password' as subtype
      from password
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listAuthMethodsPageTemplate = `
with auth_methods as (
    select public_id
      from auth_method
     where (create_time, public_id) < (@last_item_create_time, @last_item_id)
       and %s -- search condition for scope IDs is constructed
  order by create_time desc, public_id desc
     limit %d
),
ldap as (
    select *
      from ldap_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
oidc as (
    select *
      from oidc_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
password as (
    select *
      from auth_password_method_with_is_primary
     where public_id in (select public_id from auth_methods)
),
final as (
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           start_tls,
           insecure_tls,
           discover_dn,
           anon_group_search,
           upn_domain,
           enable_groups,
           use_token_groups,
           maximum_page_size,
           urls,
           certs,
           account_attribute_map,
           user_dn,
           user_attr,
           user_filter,
           group_dn,
           group_attr,
           group_filter,
           client_certificate_key,
           client_certificate_key_hmac,
           client_certificate_key_id,
           client_certificate_cert,
           bind_dn,
           bind_password,
           bind_password_hmac,
           bind_password_key_id,
           dereference_aliases,
           null as disable_discovered_config_validation, -- Add to make union uniform
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'ldap' as subtype
      from ldap
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           null as start_tls,                    -- Add to make union uniform
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           disable_discovered_config_validation,
           api_url,
           issuer,
           client_id,
           client_secret,
           client_secret_hmac,
           key_id,
           max_age,
           algs,
           auds,
           certs,
           claims_scopes,
           prompts,
           account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'oidc' as subtype
      from oidc
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           null as state,                        -- Add to make union uniform
           null as start_tls,
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           null as disable_discovered_config_validation,
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           password_conf_id,
           min_login_name_length,
           min_password_length,
           'password' as subtype
      from password
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listAuthMethodsRefreshTemplate = `
with auth_methods as (
    select public_id
      from auth_method
     where update_time > @updated_after_time
       and %s -- search condition for scope IDs is constructed
  order by update_time desc, public_id desc
     limit %d
),
ldap as (
    select *
      from ldap_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
oidc as (
    select *
      from oidc_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
password as (
    select *
      from auth_password_method_with_is_primary
     where public_id in (select public_id from auth_methods)
),
final as (
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           start_tls,
           insecure_tls,
           discover_dn,
           anon_group_search,
           upn_domain,
           enable_groups,
           use_token_groups,
           maximum_page_size,
           urls,
           certs,
           account_attribute_map,
           user_dn,
           user_attr,
           user_filter,
           group_dn,
           group_attr,
           group_filter,
           client_certificate_key,
           client_certificate_key_hmac,
           client_certificate_key_id,
           client_certificate_cert,
           bind_dn,
           bind_password,
           bind_password_hmac,
           bind_password_key_id,
           dereference_aliases,
           null as disable_discovered_config_validation, -- Add to make union uniform
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'ldap' as subtype
      from ldap
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           null as start_tls,                    -- Add to make union uniform
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           disable_discovered_config_validation,
           api_url,
           issuer,
           client_id,
           client_secret,
           client_secret_hmac,
           key_id,
           max_age,
           algs,
           auds,
           certs,
           claims_scopes,
           prompts,
           account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'oidc' as subtype
      from oidc
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           null as state,                        -- Add to make union uniform
           null as start_tls,
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           null as disable_discovered_config_validation,
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           password_conf_id,
           min_login_name_length,
           min_password_length,
           'password' as subtype
      from password
)
  select *
    from final
order by update_time desc, public_id desc;
`

	listAuthMethodsRefreshPageTemplate = `
with auth_methods as (
    select public_id
      from auth_method
     where update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
       and %s -- search condition for scope IDs is constructed
  order by update_time desc, public_id desc
     limit %d
),
ldap as (
    select *
      from ldap_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
oidc as (
    select *
      from oidc_auth_method_with_value_obj
     where public_id in (select public_id from auth_methods)
),
password as (
    select *
      from auth_password_method_with_is_primary
     where public_id in (select public_id from auth_methods)
),
final as (
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           start_tls,
           insecure_tls,
           discover_dn,
           anon_group_search,
           upn_domain,
           enable_groups,
           use_token_groups,
           maximum_page_size,
           urls,
           certs,
           account_attribute_map,
           user_dn,
           user_attr,
           user_filter,
           group_dn,
           group_attr,
           group_filter,
           client_certificate_key,
           client_certificate_key_hmac,
           client_certificate_key_id,
           client_certificate_cert,
           bind_dn,
           bind_password,
           bind_password_hmac,
           bind_password_key_id,
           dereference_aliases,
           null as disable_discovered_config_validation, -- Add to make union uniform
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'ldap' as subtype
      from ldap
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           state,
           null as start_tls,                    -- Add to make union uniform
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           disable_discovered_config_validation,
           api_url,
           issuer,
           client_id,
           client_secret,
           client_secret_hmac,
           key_id,
           max_age,
           algs,
           auds,
           certs,
           claims_scopes,
           prompts,
           account_claim_maps,
           null as password_conf_id,
           null::integer as min_login_name_length,
           null::integer as min_password_length,
           'oidc' as subtype
      from oidc
     union
    select public_id,
           scope_id,
           is_primary_auth_method,
           name,
           description,
           create_time,
           update_time,
           version,
           null as state,                        -- Add to make union uniform
           null as start_tls,
           null as insecure_tls,
           null as discover_dn,
           null as anon_group_search,
           null as upn_domain,
           null as enable_groups,
           null as use_token_groups,
           null as maximum_page_size,
           null as urls,
           null as certs,
           null as account_attribute_map,
           null as user_dn,
           null as user_attr,
           null as user_filter,
           null as group_dn,
           null as group_attr,
           null as group_filter,
           null as client_certificate_key,
           null as client_certificate_key_hmac,
           null as client_certificate_key_id,
           null as client_certificate_cert,
           null as bind_dn,
           null as bind_password,
           null as bind_password_hmac,
           null as bind_password_key_id,
           null as dereference_aliases,
           null as disable_discovered_config_validation,
           null as api_url,
           null as issuer,
           null as client_id,
           null as client_secret,
           null as client_secret_hmac,
           null as key_id,
           null as max_age,
           null as algs,
           null as auds,
           null as certs,
           null as claims_scopes,
           null as prompts,
           null as account_claim_maps,
           password_conf_id,
           min_login_name_length,
           min_password_length,
           'password' as subtype
      from password
)
  select *
    from final
order by update_time desc, public_id desc;
`
)
