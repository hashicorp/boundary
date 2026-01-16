-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

--  credential_vault_library_username_password_domain_mapping_ovrd tests:
--   the following triggers
--    insert_credential_vault_generic_library_mapping_override_subtyp
--    delete_credential_vault_generic_library_mapping_override_subtyp
--   and the following view
--    credential_vault_generic_library_list_lookup

begin;

  select plan(11);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');


  select is(count(*), 8::bigint)
    from credential_vault_generic_library_usern_pass_domain_mapping_ovrd
    where library_id in ('vl______wvl13', 'vl______wvl14', 'vl______wvl15', 'vl______wvl16', 'vl______wvl17', 'vl______wvl18', 'vl______wvl19', 'vl______wvl20');

  select is(count(*), 8::bigint)
    from credential_vault_generic_library_mapping_override
    where library_id in ('vl______wvl13', 'vl______wvl14', 'vl______wvl15', 'vl______wvl16', 'vl______wvl17', 'vl______wvl18', 'vl______wvl19', 'vl______wvl20');

  prepare select_libraries as
    select public_id::text, credential_type::text, username_attribute::text, password_attribute::text, domain_attribute::text
      from credential_vault_generic_library_list_lookup
      where public_id in ('vl______wvl2', 'vl______wvl21', 'vl______wvl13', 'vl______wvl14', 'vl______wvl15', 'vl______wvl16', 'vl______wvl17', 'vl______wvl18', 'vl______wvl19', 'vl______wvl20')
    order by public_id;

  select results_eq(
    'select_libraries',
    $$VALUES
    ('vl______wvl13', 'username_password_domain',   null,         null,          null),
    ('vl______wvl14', 'username_password_domain',  'my_username','my_password', 'my_domain'),
    ('vl______wvl15', 'username_password_domain',  'my_username', null,         'my_domain'),
    ('vl______wvl16', 'username_password_domain',   null,        'my_password', 'my_domain'),
    ('vl______wvl17', 'username_password_domain',  'my_username','my_password',  null),
    ('vl______wvl18', 'username_password_domain',  'my_username', null,          null),
    ('vl______wvl19', 'username_password_domain',   null,        'my_password',  null),
    ('vl______wvl2',  'unspecified',                null,         null,          null),
    ('vl______wvl20', 'username_password_domain',   null,         null,         'my_domain'),
    ('vl______wvl21', 'username_password_domain',   null,         null,          null)$$
  );


  -- validate insert triggers
  select is(count(*), 0::bigint) from credential_vault_generic_library_usern_pass_domain_mapping_ovrd where library_id = 'vl______wvl21';
  select is(count(*), 0::bigint) from credential_vault_generic_library_mapping_override               where library_id = 'vl______wvl21';

  prepare insert_cvl_username_password_mapping_override as
    insert into credential_vault_generic_library_usern_pass_domain_mapping_ovrd
      (library_id,username_attribute, password_attribute, domain_attribute)
    values
      ('vl______wvl21', 'my_username',      'my_password', 'my_domain');
  select lives_ok('insert_cvl_username_password_mapping_override');


  select is(count(*), 1::bigint) from credential_vault_generic_library_usern_pass_domain_mapping_ovrd where library_id = 'vl______wvl21';
  select is(count(*), 1::bigint) from credential_vault_generic_library_mapping_override               where library_id = 'vl______wvl21';

  -- validate delete triggers
  prepare delete_cvl_username_password_domain_mapping_ovrd as
    delete
      from credential_vault_generic_library_usern_pass_domain_mapping_ovrd
    where library_id = 'vl______wvl21';
  select lives_ok('delete_cvl_username_password_domain_mapping_ovrd');


  select is(count(*), 0::bigint) from credential_vault_generic_library_usern_pass_domain_mapping_ovrd where library_id = 'vl______wvl21';
  select is(count(*), 0::bigint) from credential_vault_generic_library_mapping_override               where library_id = 'vl______wvl21';

  select * from finish();
  
rollback;