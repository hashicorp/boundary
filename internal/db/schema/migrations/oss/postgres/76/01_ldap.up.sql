-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table auth_ldap_method
    add column maximum_page_size int not null default 0
      constraint maximum_page_size_greater_or_equal_to_zero
        check(
          maximum_page_size >= 0
        );

  create table auth_ldap_deref_aliases_enm (
    name text primary key
      constraint only_predefined_deref_aliases_allowed
      check (
        name in (
          'NeverDerefAliases',
          'DerefInSearching',
          'DerefFindingBaseObj',
          'DerefAlways'
        )
      )
  );
  comment on table auth_ldap_deref_aliases_enm is
    'auth_ldap_deref_alias_enm is an enumeration table for ldap deref aliases.'
    'It contains rows for representing the NeverDerefAliases, DerefInSearching, ' 
    'DerefFindingBaseObj, and DerefAlways deref aliasing.';

  insert into auth_ldap_deref_aliases_enm (name)
  values
    ('NeverDerefAliases'),
    ('DerefInSearching'),
    ('DerefFindingBaseObj'),
    ('DerefAlways');

  create table auth_ldap_deref_aliases (
    create_time wt_timestamp,
    ldap_method_id wt_public_id primary key
      constraint auth_ldap_method_fkey
        references auth_ldap_method (public_id)
        on delete cascade
        on update cascade,
    dereference_aliases text not null
      constraint auth_ldap_deref_aliases_enm_fkey
        references auth_ldap_deref_aliases_enm (name)
        on delete cascade
        on update cascade
  );
  comment on table auth_ldap_deref_aliases is 
  'auth_ldap_deref_aliases are optional and specify how Boundary should handle '
  'dereferencing aliases durning LDAP searches';

  -- replaces view from 65/01_ldap.up.sql
  drop view ldap_auth_method_with_value_obj;
  -- ldap_auth_method_with_value_obj is useful for reading an ldap auth method 
  -- with its associated value objects (urls, certs, search config, etc). The use
  -- of the postgres string_agg(...) to aggregate the url and cert value objects
  -- into a column works because we are only pulling in one column from the
  -- associated tables and that value is part of the primary key and unique.  This
  -- view will make things like recursive listing of ldap auth methods fairly
  -- straightforward to implement for the ldap repo.  The view also includes an
  -- is_primary_auth_method bool
  create view ldap_auth_method_with_value_obj as 
  select 
    case when s.primary_auth_method_id is not null then
      true
    else false end
    as is_primary_auth_method,
    am.public_id,
    am.scope_id,
    am.name,
    am.description,
    am.create_time,
    am.update_time,
    am.version,
    am.state,
    am.start_tls,
    am.insecure_tls,
    am.discover_dn,
    am.anon_group_search,
    am.upn_domain,
    am.enable_groups,
    am.use_token_groups,
    am.maximum_page_size,
    -- the string_agg(..) column will be null if there are no associated value objects
    string_agg(distinct url.url, '|') as urls,
    string_agg(distinct cert.certificate, '|') as certs,
    string_agg(distinct concat_ws('=', aam.from_attribute, aam.to_attribute), '|') as account_attribute_map,
    
    -- the rest of the fields are zero to one relationships that are stored in
    -- related tables. Since we're outer joining with these tables, we need to
    -- either add them to the group by, use an aggregating func, or handle
    -- multiple rows returning for each auth method. I've chosen to just use
    -- string_agg(...) 
    string_agg(distinct uc.user_dn, '|') as user_dn, 
    string_agg(distinct uc.user_attr, '|') as user_attr, 
    string_agg(distinct uc.user_filter, '|') as user_filter, 
    string_agg(distinct gc.group_dn, '|') as group_dn, 
    string_agg(distinct gc.group_attr, '|') as group_attr, 
    string_agg(distinct gc.group_filter, '|') as group_filter, 
    string_agg(distinct cc.certificate_key, '|') as client_certificate_key, 
    string_agg(distinct cc.certificate_key_hmac, '|') as client_certificate_key_hmac, 
    string_agg(distinct cc.key_id, '|') as client_certificate_key_id, 
    string_agg(distinct cc.certificate, '|') as client_certificate_cert,
    string_agg(distinct bc.dn, '|') as bind_dn, 
    string_agg(distinct bc.password, '|') as bind_password, 
    string_agg(distinct bc.password_hmac, '|') as bind_password_hmac,
    string_agg(distinct bc.key_id, '|') as bind_password_key_id,
    string_agg(distinct df.dereference_aliases, '|') as dereference_aliases
  from 	
    auth_ldap_method am 
    left outer join iam_scope                       s     on am.public_id = s.primary_auth_method_id 
    left outer join auth_ldap_url                   url   on am.public_id = url.ldap_method_id
    left outer join auth_ldap_certificate           cert  on am.public_id = cert.ldap_method_id
    left outer join auth_ldap_account_attribute_map aam   on am.public_id = aam.ldap_method_id
    left outer join auth_ldap_user_entry_search     uc    on am.public_id = uc.ldap_method_id
    left outer join auth_ldap_group_entry_search    gc    on am.public_id = gc.ldap_method_id
    left outer join auth_ldap_client_certificate    cc    on am.public_id = cc.ldap_method_id
    left outer join auth_ldap_bind_credential       bc    on am.public_id = bc.ldap_method_id
    left outer join auth_ldap_deref_aliases         df    on am.public_id = df.ldap_method_id
  group by am.public_id, is_primary_auth_method; -- there can be only one public_id + is_primary_auth_method, so group by isn't a problem.
  comment on view ldap_auth_method_with_value_obj is
    'ldap auth method with its associated value objects (urls, certs, search config, etc)';

commit;