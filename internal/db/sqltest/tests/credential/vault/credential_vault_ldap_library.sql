-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  select lives_ok(
    $$
      insert into credential_vault_ldap_library
        (store_id,       public_id,        vault_path,                                 credential_type)
      values
        ('vs_______wvs', 'vl______vlsc1',  '/ldap/static-cred/foo',                    'username_password_domain'),
        ('vs_______wvs', 'vl______vlsc2',  '/ldap/static-cred/foo/bar',                'username_password_domain'),
        ('vs_______wvs', 'vl______vlsc3',  '/ldap/static-cred/foo/bar/baz',            'username_password_domain'),
        ('vs_______wvs', 'vl______vlsc4',  '/ldap/static-cred/foo/bar/baz/more/paths', 'username_password_domain'),
        ('vs_______wvs', 'vl______vldyn5', '/ldap/creds/foo',                          'username_password_domain'),
        ('vs_______wvs', 'vl______vldyn6', '/ldap/creds/foo/bar/baz/more/paths',       'username_password_domain'),
        ('vs_______wvs', 'vl______vldyn7', '/ldap/creds/foo/bar/baz',                  'something_that_doesnt_exist');
    $$
  );

  select results_eq(
    $$
        select public_id, project_id, store_id, name, description, vault_path, credential_type
          from credential_vault_ldap_library
         where public_id like 'vl______vlsc%'
            or public_id like 'vl______vldyn%'
      order by public_id;
    $$,
    $$
      values
        ('vl______vldyn5'::wt_public_id, 'p____bwidget'::wt_public_id, 'vs_______wvs'::wt_public_id, null::wt_name, null::wt_description, '/ldap/creds/foo',                          'username_password_domain'),
        ('vl______vldyn6'::wt_public_id, 'p____bwidget'::wt_public_id, 'vs_______wvs'::wt_public_id, null::wt_name, null::wt_description, '/ldap/creds/foo/bar/baz/more/paths',       'username_password_domain'),
        ('vl______vldyn7'::wt_public_id, 'p____bwidget'::wt_public_id, 'vs_______wvs'::wt_public_id, null::wt_name, null::wt_description, '/ldap/creds/foo/bar/baz',                  'username_password_domain'),
        ('vl______vlsc1'::wt_public_id,  'p____bwidget'::wt_public_id, 'vs_______wvs'::wt_public_id, null::wt_name, null::wt_description, '/ldap/static-cred/foo',                    'username_password_domain'),
        ('vl______vlsc2'::wt_public_id,  'p____bwidget'::wt_public_id, 'vs_______wvs'::wt_public_id, null::wt_name, null::wt_description, '/ldap/static-cred/foo/bar',                'username_password_domain'),
        ('vl______vlsc3'::wt_public_id,  'p____bwidget'::wt_public_id, 'vs_______wvs'::wt_public_id, null::wt_name, null::wt_description, '/ldap/static-cred/foo/bar/baz',            'username_password_domain'),
        ('vl______vlsc4'::wt_public_id,  'p____bwidget'::wt_public_id, 'vs_______wvs'::wt_public_id, null::wt_name, null::wt_description, '/ldap/static-cred/foo/bar/baz/more/paths', 'username_password_domain');
    $$
  );

  select row_eq(
    $$
        select count(*)
          from credential_vault_library
         where public_id like 'vl______vlsc%'
            or public_id like 'vl______vldyn%';
    $$,
    row(7::bigint)
  );

  select row_eq(
    $$
        select count(*)
          from credential_library
         where public_id like 'vl______vlsc%'
            or public_id like 'vl______vldyn%';
    $$,
    row(7::bigint)
  );

  select * from finish();
rollback;
