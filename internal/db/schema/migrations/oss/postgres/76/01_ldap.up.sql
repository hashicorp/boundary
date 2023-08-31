-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;


  alter table auth_ldap_method
    add column maximum_page_size int not null default 0;

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
  comment on table auth_ldap_bind_credential is 
  'auth_ldap_deref_aliases are optional and specify how Boundary should handle '
  'dereferencing aliases durning LDAP searches';

  alter table auth_ldap_method
    add column dereference_aliases text not null default 'NeverDerefAliases'
      constraint auth_ldap_deref_aliases_enm_fkey
        references auth_ldap_deref_aliases_enm (name)
        on delete cascade
        on update cascade;

commit;