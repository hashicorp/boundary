-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- There is a theme to the data in this file.
-- There is an Organization called Colors R Us.
-- Colors R Us has a project for each of their color mills: the Blue Color Mill,
-- the Red Color Mill, and the Green Color Mill.
-- Public IDs are all created to make it easy to understand what the resource is
-- and what resource owns that resource.

-- The sql insert statements are arranged to facilitate copying and pasting
-- which makes additions easier. Please take the time to understand the
-- patterns and follow them whenever possible.

-- When adding items to this file, please follow these guidelines:
-- For new IDs:
-- * make them exactly 12 characters long
-- * use a prefix of 1-3 character to indicate the table
-- * the characters 5-12 are the id:
--     - for resources, the ending characters indicate either blue, red, or green
--       and a number if more than one is needed
--     - for users, sessions, or session recordings indicate the user and plus a
--       number if more than one is needed
-- * add _ characters between the prefix and the id to get to an ID size of 12
--
-- Using IDs of 12 characters allows alignment of insert values and makes
-- spotting issues easier. It also makes copying and pasting easier.
--
-- In general, the order of the columns for insert statements should be
-- For insert statements, try to order your columns so that repeating values are
-- first, followed by the new unique id (public_id or private_id), and then
-- optional or non-standard columns.

begin;
  -- Add organizations
  insert into iam_scope
    (parent_id, type,  public_id,      name)
  values
    ('global',  'org', 'o_____colors', 'Colors R Us');

  -- Add projects to the organizations
  insert into iam_scope
    (parent_id,      type,      public_id,      name)
  values
    ('o_____colors', 'project', 'p____bcolors', 'Blue Color Mill'),
    ('o_____colors', 'project', 'p____rcolors', 'Red Color Mill'),
    ('o_____colors', 'project', 'p____gcolors', 'Green Color Mill');

  -- Global user names start with a G to indicate global.
  -- Nancy is a special case. N stands for none, not assigned, etc.
  -- Nancy has no permissions.
  insert into iam_user
    (scope_id, public_id,      name)
  values
    ('global', 'u_______gary', 'Gary'),
    ('global', 'u_______gina', 'Gina'),
    ('global', 'u______nancy', 'Nancy');

  -- User's in the Colors organization have names that start with C to indicate
  -- Colors.
  insert into iam_user
    (scope_id,       public_id,      name)
  values
    ('o_____colors', 'u______clare', 'Clare'),
    ('o_____colors', 'u______cindy', 'Cindy'),
    ('o_____colors', 'u______carly', 'Carly'),
    ('o_____colors', 'u______ciara', 'Ciara'),
    ('o_____colors', 'u_______cora', 'Cora');

  insert into kms_root_key
    (scope_id,       private_id)
  values
    ('o_____colors', 'krk___colors');

  insert into kms_root_key_version
    (root_key_id,    private_id,     key)
  values
    ('krk___colors', 'krkv__colors', '_______color1'::bytea);

  insert into kms_data_key
    (root_key_id,    private_id,     purpose)
  values
    ('krk___colors', 'kdk___colors', 'database');

  insert into kms_data_key_version
    (root_key_version_id, data_key_id,    private_id,     key)
  values
	  ('krkv__colors',      'kdk___colors', 'kdkv__colors', '_______color2'::bytea);

  insert into iam_group
    (scope_id,       public_id,      name)
  values
    ('global',       'g___gg-group', 'Global Group'),
    ('o_____colors', 'g___oc-group', 'Colors R Us Group'),
    ('p____bcolors', 'g___cb-group', 'Blue Color Group'),
    ('p____rcolors', 'g___cr-group', 'Red Color Group'),
    ('p____gcolors', 'g___cg-group', 'Green Color Group');

  insert into iam_group_member_user
    (group_id,       member_id)
  values
    ('g___gg-group', 'u_______gary'),
    ('g___oc-group', 'u______clare'),
    ('g___cb-group', 'u______cindy'),
    ('g___cr-group', 'u______carly'),
    ('g___cg-group', 'u_______cora');

  insert into iam_role_global
    (scope_id,       public_id,      name,      grant_this_role_scope,      grant_scope)
  values
    ('global', 'r_go____name', 'Color Namer', false, 'individual'),
    ('global', 'r_gp____spec', 'Blue Color Inspector', false, 'individual'),
    ('global', 'r_gg_____buy', 'Purchaser', true, 'individual'),
    ('global', 'r_gg____shop', 'Shopper', true, 'individual');

  insert into iam_role_global_individual_org_grant_scope
    (role_id,       scope_id,       grant_scope)
  values
    ('r_go____name', 'o_____colors', 'individual');

  insert into iam_role_global_individual_project_grant_scope
    (role_id,       scope_id,       grant_scope)
  values
    ('r_gp____spec', 'p____bcolors', 'individual');


  insert into iam_role_org
    (scope_id,       public_id,      name,      grant_this_role_scope,      grant_scope)
  values
    ('o_____colors', 'r_op_bc__art', 'Blue Color Artist', false, 'individual'),
    ('o_____colors', 'r_op_rc__art', 'Red Color Artist', false, 'individual'),
    ('o_____colors', 'r_op_gc__art', 'Green Color Artist', false, 'individual'),
    ('o_____colors', 'r_oo_____art', 'Color Artist', false, 'individual');

  insert into iam_role_org_individual_grant_scope
    (role_id,       scope_id,       grant_scope)
  values
    ('r_op_bc__art', 'p____bcolors', 'individual'),
    ('r_op_rc__art', 'p____rcolors', 'individual'),
    ('r_op_gc__art', 'p____gcolors', 'individual');


  insert into iam_role_project
    (scope_id,       public_id,      name,      grant_this_role_scope)
  values
    ('p____bcolors', 'r_pp_bc__mix', 'Color Mixer', true),
    ('p____rcolors', 'r_pp_rc__mix', 'Color Mixer', true),
    ('p____gcolors', 'r_pp_gc__mix', 'Color Mixer', true);

  insert into iam_role_grant
    (role_id,        canonical_grant,                                    raw_grant)
  values
    ('r_gg_____buy', 'ids=*;type=*;actions=update',                      'ids=*;type=*;actions=update'),
    ('r_gg____shop', 'ids=*;type=*;actions=read;output_fields=id',       'ids=*;type=*;actions=read;output_fields=id'),
    ('r_go____name', 'ids=*;type=group;actions=create,update,read,list', 'ids=*;type=group;actions=create,update,read,'),
    ('r_gp____spec', 'ids=*;type=group;actions=delete',                  'ids=*;type=group;actions=delete'),
    ('r_oo_____art', 'ids=*;type=group;actions=create',                  'ids=*;type=group;actions=create'),
    ('r_op_bc__art', 'ids=*;type=auth-token;actions=create',             'ids=*;type=auth-token;actions=create'),
    ('r_op_rc__art', 'ids=*;type=target;actions=create',                 'ids=*;type=targets;actions=create'),
    ('r_op_gc__art', 'ids=*;type=auth-method;actions=authenticate',      'ids=*;type=auth-method;actions=create'),
    ('r_pp_bc__mix', 'ids=*;type=group;actions=add-members',             'ids=*;type=group;actions=add-members'),
    ('r_pp_rc__mix', 'ids=*;type=group;actions=set-members',             'ids=*;type=group;actions=set-members'),
    ('r_pp_gc__mix', 'ids=*;type=group;actions=delete-members',          'ids=*;type=group;actions=delete-members');

  insert into iam_group_role
    (role_id,        principal_id)
  values
    ('r_op_rc__art', 'g___oc-group'), -- color
    ('r_pp_bc__mix', 'g___cb-group'), -- color
    ('r_pp_rc__mix', 'g___cr-group'), -- color
    ('r_pp_gc__mix', 'g___cg-group'); -- color

  insert into iam_user_role
    (role_id,        principal_id)
  values
    ('r_go____name', 'u_______gary'),
    ('r_gp____spec', 'u_______gina'),
    ('r_gg_____buy', 'u_auth'),
    ('r_gg____shop', 'u_anon');

  insert into auth_password_conf
    (password_method_id, private_id)
  values
    ('apm___colors',     'apmc__colors');

  -- Add password auth method to organizations
  insert into auth_password_method
    (scope_id,       public_id,      password_conf_id, name)
  values
    ('o_____colors', 'apm___colors', 'apmc__colors',   'Colors Auth Password');

  insert into auth_password_account
    (auth_method_id, public_id,      login_name)
  values
    ('apm___colors', 'apa____clare', 'clare'),
    ('apm___colors', 'apa____cindy', 'cindy'),
    ('apm___colors', 'apa____carly', 'carly'),
    ('apm___colors', 'apa_____cora', 'cora'),
    ('apm___colors', 'apa____ciara', 'ciara');

  update auth_account set iam_user_id = 'u______clare' where public_id = 'apa____clare';
  update auth_account set iam_user_id = 'u______cindy' where public_id = 'apa____cindy';
  update auth_account set iam_user_id = 'u______carly' where public_id = 'apa____carly';
  update auth_account set iam_user_id = 'u_______cora' where public_id = 'apa_____cora';
  update auth_account set iam_user_id = 'u______ciara' where public_id = 'apa____ciara';

  insert into static_host_catalog
    (project_id,     public_id,      name)
  values
    ('p____bcolors', 'hc__st_____b', 'Blue Color Static Catalog'),
    ('p____rcolors', 'hc__st_____r', 'Red Color Static Catalog'),
    ('p____gcolors', 'hc__st_____g', 'Green Color Static Catalog');

  insert into auth_token
    (key_id,         auth_account_id, public_id,      token,                 expiration_time,            status)
  values
    ('kdkv__colors', 'apa____clare',  'tok____clare', 'tok____clare'::bytea, now() + interval '15 days', 'token issued'),
    ('kdkv__colors', 'apa____cindy',  'tok____cindy', 'tok____cindy'::bytea, now() + interval '15 days', 'token issued'),
    ('kdkv__colors', 'apa____ciara',  'tok____ciara', 'tok____ciara'::bytea, now() + interval '15 days', 'auth token pending'),
    ('kdkv__colors', 'apa____carly',  'tok____carly', 'tok____carly'::bytea, now() + interval '15 days', 'token issued'),
    ('kdkv__colors', 'apa_____cora',  'tok_____cora', 'tok_____cora'::bytea, now() + interval '15 days', 'auth token pending');

  insert into static_host
    (catalog_id,     public_id,      address)
  values
    ('hc__st_____b', 'h___st____b1', '1.blue.color'),
    ('hc__st_____b', 'h___st____b2', '2.blue.color'),
    ('hc__st_____b', 'h___st____b3', '3.blue.color'),
    ('hc__st_____b', 'h___st____b4', '4.blue.color'),
    ('hc__st_____b', 'h___st____b5', '5.blue.color'),
    ('hc__st_____b', 'h___st____b6', '6.blue.color'),
    ('hc__st_____b', 'h___st____b7', '7.blue.color'),
    ('hc__st_____b', 'h___st____b8', '8.blue.color'),
    ('hc__st_____b', 'h___st____b9', '9.blue.color'),

    ('hc__st_____r', 'h___st____r1', '1.red.color'),
    ('hc__st_____r', 'h___st____r2', '2.red.color'),
    ('hc__st_____r', 'h___st____r3', '3.red.color'),
    ('hc__st_____r', 'h___st____r4', '4.red.color'),
    ('hc__st_____r', 'h___st____r5', '5.red.color'),
    ('hc__st_____r', 'h___st____r6', '6.red.color'),
    ('hc__st_____r', 'h___st____r7', '7.red.color'),
    ('hc__st_____r', 'h___st____r8', '8.red.color'),
    ('hc__st_____r', 'h___st____r9', '9.red.color'),

    ('hc__st_____g', 'h___st____g1', '1.green.color'),
    ('hc__st_____g', 'h___st____g2', '2.green.color'),
    ('hc__st_____g', 'h___st____g3', '3.green.color'),
    ('hc__st_____g', 'h___st____g4', '4.green.color'),
    ('hc__st_____g', 'h___st____g5', '5.green.color'),
    ('hc__st_____g', 'h___st____g6', '6.green.color'),
    ('hc__st_____g', 'h___st____g7', '7.green.color'),
    ('hc__st_____g', 'h___st____g8', '8.green.color'),
    ('hc__st_____g', 'h___st____g9', '9.green.color');

  insert into host_dns_name
    (host_id,        name)
  values
    -- note there are no dns names for blue 1
    ('h___st____b2', '2.blue.color'),
    ('h___st____b3', '3.blue.color'),
    ('h___st____b4', '4.blue.color'),
    ('h___st____b5', '5.blue.color'),
    ('h___st____b6', '6.blue.color'),
    ('h___st____b7', '7.blue.color'),
    ('h___st____b8', '8.blue.color'),
    ('h___st____b9', '9.blue.color'),

    ('h___st____r2', '1.red.color'),
    ('h___st____r2', '2.red.color'),
    ('h___st____r3', '3.red.color'),
    ('h___st____r4', '4.red.color'),
    ('h___st____r5', '5.red.color'),
    ('h___st____r6', '6.red.color'),
    ('h___st____r7', '7.red.color'),
    ('h___st____r8', '8.red.color'),
    ('h___st____r9', '9.red.color'),

    ('h___st____g1', '1.green.color'),
    ('h___st____g2', '2.green.color'),
    ('h___st____g3', '3.green.color'),
    ('h___st____g4', '4.green.color'),
    ('h___st____g5', '5.green.color'),
    ('h___st____g6', '6.green.color'),
    ('h___st____g7', '7.green.color'),
    ('h___st____g8', '8.green.color'),
    ('h___st____g9', '9.green.color');

  insert into host_ip_address
    (host_id,        address)
  values
    -- note there are no address for blue 1
    ('h___st____b2', '10.0.0.2'),
    ('h___st____b3', 'fe80::3333:3333:3333:3333'),
    ('h___st____b4', '10.0.0.4'),
    ('h___st____b5', 'fe80::5555:5555:5555:5555'),
    ('h___st____b6', '10.0.0.6'),
    ('h___st____b7', 'fe80::7777:7777:7777:7777'),
    ('h___st____b8', '10.0.0.8'),
    ('h___st____b9', 'fe80::9999:9999:9999:9999'),

    ('h___st____r1', '11.11.11.11'),
    ('h___st____r2', '2001:4860:4860::2222'),
    ('h___st____r3', '33.33.33.33'),
    ('h___st____r4', '2001:4860:4860::4444'),
    ('h___st____r5', '55.55.55.55'),
    ('h___st____r6', '2001:4860:4860::6666'),
    ('h___st____r7', '77.77.77.77'),
    ('h___st____r8', '2001:4860:4860::8888'),
    ('h___st____r9', '99.99.99.99'),

    ('h___st____g1', '111.111.111.111'),
    ('h___st____g2', '3001:5860:5860::3333'),
    ('h___st____g3', '112.112.112.112'),
    ('h___st____g4', '3001:5860:5860::5555'),
    ('h___st____g5', '113.113.113.113'),
    ('h___st____g6', '3001:5860:5860::7777'),
    ('h___st____g7', '114.114.114.114'),
    ('h___st____g8', '3001:5860:5860::9999'),
    ('h___st____g9', '115.115.115.115');

  insert into static_host_set
    (catalog_id,     public_id,      name)
  values
    ('hc__st_____b', 'hs__st____b1', 'Blue Color Static Set 1'),
    ('hc__st_____b', 'hs__st____b2', 'Blue Color Static Set 2'),
    ('hc__st_____r', 'hs__st____r1', 'Red Color Static Set 1'),
    ('hc__st_____r', 'hs__st____r2', 'Red Color Static Set 2'),
    ('hc__st_____g', 'hs__st____g1', 'Green Color Static Set 1'),
    ('hc__st_____g', 'hs__st____g2', 'Green Color Static Set 2');

  insert
    into static_host_set_member
         ( host_id,     set_id,      catalog_id)
  select h.public_id, s.public_id, s.catalog_id
    from static_host as h,
         static_host_set as s
   where h.catalog_id = s.catalog_id;

  insert into plugin
    (scope_id, public_id,      name)
  values
    ('global', 'plg____chost', 'Colors Host Plugin');

  insert into plugin_host_supported
    (public_id)
  values
    ('plg____chost');

  insert into host_plugin_catalog
    (project_id,     plugin_id,      public_id,      name,                        attributes)
  values
    ('p____bcolors', 'plg____chost', 'hc__plg____b', 'Blue Color Plugin Catalog', ''),
    ('p____rcolors', 'plg____chost', 'hc__plg____r', 'Red Color Plugin Catalog',  '');

  insert into host_plugin_host
    (catalog_id,     public_id,      external_id)
  values
    ('hc__plg____b', 'h___plg___b1', '1 blue color'),
    ('hc__plg____b', 'h___plg___b2', '2 blue color'),
    ('hc__plg____b', 'h___plg___b3', '3 blue color'),

    ('hc__plg____r', 'h___plg___r1', '1 red color'),
    ('hc__plg____r', 'h___plg___r2', '2 red color'),
    ('hc__plg____r', 'h___plg___r3', '3 red color');

  insert into host_dns_name
    (host_id,        name)
  values
    ('h___plg___b1', '1.blue.color'),
    ('h___plg___b2', '2.blue.color'),
    ('h___plg___b3', '3.blue.color'),

    ('h___plg___r1', '1.red.color'),
    ('h___plg___r2', '2.red.color'),
    ('h___plg___r3', '3.red.color');

  insert into host_ip_address
    (host_id,        address)
  values
    ('h___plg___b1', '1.1.1.1'),
    ('h___plg___b2', 'fe80::2222:2222:2222:2222'),
    -- host 3 only has a dns name so the set of addresses are the same
    -- between the static and plugin based host

    ('h___plg___r1', '11.11.11.11'),
    ('h___plg___r2', '2001:4860:4860::2222'),
    ('h___plg___r3', '33.33.33.33');

  insert into host_plugin_set
    (catalog_id,     public_id,      name,                      attributes, need_sync)
  values
    ('hc__plg____b', 'hs__plg___b1', 'Blue Color Plugin Set 1', '',         false),
    ('hc__plg____b', 'hs__plg___b2', 'Blue Color Plugin Set 2', '',         false),
    ('hc__plg____r', 'hs__plg___r1', 'Red Color Plugin Set 1',  '',         false),
    ('hc__plg____r', 'hs__plg___r2', 'Red Color Plugin Set 2',  '',         false);

  insert
    into host_plugin_set_member
         ( host_id,     set_id,      catalog_id)
  select h.public_id, s.public_id, s.catalog_id
    from host_plugin_host as h,
         host_plugin_set as s
   where h.catalog_id = s.catalog_id
     and h.external_id like '%color';

  insert into plugin
    (scope_id, public_id,      name)
  values
    ('global', 'pl__plg___sb', 'Storage Bucket Plugin');

  insert into plugin_storage_supported
    (public_id)
  values
    ('pl__plg___sb');

  insert into storage_bucket_credential_environmental
    (private_id, storage_bucket_id)
  values
    ('sbc___global', 'sb____global'),
    ('sbc___colors', 'sb____colors');

  insert into storage_plugin_storage_bucket
    (plugin_id,      scope_id,       public_id,      bucket_name,             worker_filter,        secrets_hmac, storage_bucket_credential_id)
  values
    ('pl__plg___sb', 'global',       'sb____global', 'Global Storage Bucket', 'test worker filter', '\xdeadbeef', 'sbc___global'),
    ('pl__plg___sb', 'o_____colors', 'sb____colors', 'Colors Storage Bucket', 'test worker filter', '\xdeadbeef', 'sbc___colors');

  insert into target_tcp
    (project_id,     public_id,      name)
  values
    ('p____bcolors', 't_________cb', 'Blue Color Target'),
    ('p____rcolors', 't_________cr', 'Red Color Target'),
    ('p____gcolors', 't_________cg', 'Green Color Target');

  insert into target_ssh
    (project_id,     public_id,      name,                     enable_session_recording, storage_bucket_id)
  values
    ('p____bcolors', 'tssh______cb', 'Blue Color SSH Target',  true,                     'sb____global'),
    ('p____rcolors', 'tssh______cr', 'Red Color SSH Target',   false,                    null),
    ('p____gcolors', 'tssh______cg', 'Green Color SSH Target', true,                     'sb____colors');

  insert into target_rdp
    (project_id,     public_id,      name,                     enable_session_recording, storage_bucket_id)
  values
    ('p____bcolors', 'trdp______cb', 'Blue Color RDP Target',  true,                     'sb____global'),
    ('p____rcolors', 'trdp______cr', 'Red Color RDP Target',   false,                    null),
    ('p____gcolors', 'trdp______cg', 'Green Color RDP Target', true,                     'sb____colors');

  insert into target_host_set
    (project_id,     target_id,      host_set_id)
  values
    ('p____bcolors', 't_________cb', 'hs__st____b1'),
    ('p____bcolors', 't_________cb', 'hs__st____b2'),
    ('p____rcolors', 't_________cr', 'hs__st____r1'),
    ('p____rcolors', 't_________cr', 'hs__st____r2'),
    ('p____bcolors', 'tssh______cb', 'hs__st____b1'),
    ('p____bcolors', 'tssh______cb', 'hs__st____b2'),
    ('p____bcolors', 'tssh______cb', 'hs__plg___b1'),
    ('p____rcolors', 'tssh______cr', 'hs__st____r1'),
    ('p____rcolors', 'tssh______cr', 'hs__st____r2'),
    ('p____bcolors', 'trdp______cb', 'hs__st____b1'),
    ('p____bcolors', 'trdp______cb', 'hs__st____b2'),
    ('p____bcolors', 'trdp______cb', 'hs__plg___b1'),
    ('p____rcolors', 'trdp______cr', 'hs__st____r1'),
    ('p____rcolors', 'trdp______cr', 'hs__st____r2');

  insert into target_address
    (target_id,      address)
  values
    ('t_________cg', '8.8.8.8'),
    ('tssh______cg', '8.8.8.8'),
    ('trdp______cg', '8.8.8.8');

  insert into credential_vault_store
    (project_id,     public_id,      name,                description, vault_address,               namespace)
  values
    ('p____bcolors', 'cvs__bcolors', 'blue vault store',  'None',      'https://blue.vault.color',  'blue'),
    ('p____rcolors', 'cvs__rcolors', 'red vault store',   'Some',      'https://red.vault.color',   'red'),
    ('p____gcolors', 'cvs__gcolors', 'green vault store', 'Maybe',     'https://green.vault.color', 'green');

  insert into credential_vault_generic_library
    (store_id,       public_id,      name,                  description, vault_path, http_method)
  values
    ('cvs__bcolors', 'cvl_______b1', 'blue vault library',  'None',      '/secrets', 'GET'),
    ('cvs__rcolors', 'cvl_______r1', 'red vault library',   'None',      '/secrets', 'GET'),
    ('cvs__gcolors', 'cvl_______g1', 'green vault library', 'None',      '/secrets', 'GET');

  insert into credential_vault_ssh_cert_library
    (store_id,       public_id,      name,                      vault_path,         username, key_type,  key_bits)
  values
    ('cvs__bcolors', 'cvl__ssh__b1', 'blue vault ssh library',  '/ssh/sign/blue',   'admin',  'ed25519', 0),
    ('cvs__rcolors', 'cvl__ssh__r1', 'red vault ssh library',   '/ssh/issue/red',   'webdev', 'ecdsa',   521),
    ('cvs__gcolors', 'cvl__ssh__g1', 'green vault ssh library', '/ssh/issue/green', 'dba',    'rsa',     4096);

  insert into credential_vault_ldap_library
    (store_id,       public_id,      name,                       vault_path,                                                 credential_type)
   values
    ('cvs__bcolors', 'cvl__ldap_b1', 'blue vault ldap library',  '/ldap/static-cred/blue',                                   'username_password_domain'),
    ('cvs__rcolors', 'cvl__ldap_r1', 'red vault ldap library',   '/ldap/creds/red',                                          'username_password_domain'),
    ('cvs__gcolors', 'cvl__ldap_g1', 'green vault ldap library', '/ldap/static-cred/org-colors-r-us/group-green-color/green','username_password_domain');

  insert into credential_static_store
    (project_id,     public_id,      name,                            description)
  values
    ('p____bcolors', 'css__bcolors', 'Blue Static Credential Store',  'Static Credential Store for the Blue project'),
    ('p____rcolors', 'css__rcolors', 'Red Static Credential Store',   'Static Credential Store for the Red project'),
    ('p____gcolors', 'css__gcolors', 'Green Static Credential Store', 'Static Credential Store for the Green project');

  insert into credential_static_json_credential
    (key_id,         project_id,     store_id,       public_id,      name,              object_encrypted,   object_hmac)
  values
    ('kdkv__colors', 'p____bcolors', 'css__bcolors', 'csj__bcolors', 'Blue json cred',  'bjson-enc'::bytea, 'bjson-hmac'::bytea),
    ('kdkv__colors', 'p____rcolors', 'css__rcolors', 'csj__rcolors', 'Red json cred',   'rjson-enc'::bytea, 'rjson-hmac'::bytea),
    ('kdkv__colors', 'p____gcolors', 'css__gcolors', 'csj__gcolors', 'Green json cred', 'gjson-enc'::bytea, 'gjson-hmac'::bytea);

  insert into credential_static_username_password_credential
    (key_id,         project_id,     store_id,       public_id,      name,                           username, password_encrypted,   password_hmac)
  values
    ('kdkv__colors', 'p____bcolors', 'css__bcolors', 'csu__bcolors', 'Blue username password cred',  'buser',  'bpasswd-enc'::bytea, 'bpasswd-hmac'::bytea),
    ('kdkv__colors', 'p____rcolors', 'css__rcolors', 'csu__rcolors', 'Red username password cred',   'ruser',  'rpasswd-enc'::bytea, 'rpasswd-hmac'::bytea),
    ('kdkv__colors', 'p____gcolors', 'css__gcolors', 'csu__gcolors', 'Green username password cred', 'guser',  'gpasswd-enc'::bytea, 'gpasswd-hmac'::bytea);

  insert into credential_static_username_password_domain_credential
    (key_id,         project_id,     store_id,       public_id,      name,                           username,  password_encrypted,   password_hmac,         domain)
    values
    ('kdkv__colors', 'p____bcolors', 'css__bcolors', 'csud_bcolors', 'Blue username password cred',  'buser',   'bpasswd-enc'::bytea, 'bpasswd-hmac'::bytea, 'blue.domain'),
    ('kdkv__colors', 'p____rcolors', 'css__rcolors', 'csud_rcolors', 'Red username password cred',   'ruser',   'rpasswd-enc'::bytea, 'rpasswd-hmac'::bytea, 'red.domain'),
    ('kdkv__colors', 'p____gcolors', 'css__gcolors', 'csud_gcolors', 'Green username password cred', 'guser',   'gpasswd-enc'::bytea, 'gpasswd-hmac'::bytea, 'green.domain');

  insert into credential_static_ssh_private_key_credential
    (key_id,         project_id,     store_id,       public_id,      name,                           username, private_key_encrypted, private_key_hmac)
  values
    ('kdkv__colors', 'p____bcolors', 'css__bcolors', 'cspk_bcolors', 'Blue username password cred',  'buser',  'bprivkey-enc'::bytea, 'bprivkey-hmac'::bytea),
    ('kdkv__colors', 'p____rcolors', 'css__rcolors', 'cspk_rcolors', 'Red username password cred',   'ruser',  'rprivkey-enc'::bytea, 'rprivkey-hmac'::bytea),
    ('kdkv__colors', 'p____gcolors', 'css__gcolors', 'cspk_gcolors', 'Green username password cred', 'guser',  'gprivkey-enc'::bytea, 'gprivkey-hmac'::bytea);

  insert into target_static_credential
    (project_id,     target_id,      credential_static_id, credential_purpose)
  values
    ('p____bcolors', 't_________cb', 'csj__bcolors',       'brokered'),
    ('p____bcolors', 'tssh______cb', 'csj__bcolors',       'injected_application'),
    ('p____gcolors', 'tssh______cg', 'csj__gcolors',       'brokered'),
    ('p____gcolors', 'tssh______cg', 'csu__gcolors',       'brokered'),
    ('p____gcolors', 'tssh______cg', 'cspk_gcolors',       'injected_application'),
    ('p____gcolors', 'tssh______cg', 'csud_gcolors',       'brokered');
    ;

  insert into target_credential_library
    (project_id,     target_id,      credential_library_id, credential_purpose)
  values
    ('p____bcolors', 't_________cb', 'cvl_______b1',        'brokered'),
    ('p____bcolors', 'tssh______cb', 'cvl__ssh__b1',        'brokered'),
    ('p____gcolors', 'tssh______cg', 'cvl_______g1',        'brokered'),
    ('p____gcolors', 'tssh______cg', 'cvl__ssh__g1',        'injected_application');

  insert into alias_target
    (scope_id, public_id,      value,              destination_id)
  values
    ('global', 'alt__t____cb', 'blue.tcp.target',  't_________cb'),
    ('global', 'alt__t____cr', 'red.tcp.target',   't_________cr'),
    ('global', 'alt__t____cg', 'green.tcp.target', 't_________cg'),
    ('global', 'alt__tssh_cb', 'blue.ssh.target',  'tssh______cb'),
    ('global', 'alt__tssh_cr', 'red.ssh.target',   'tssh______cr'),
    ('global', 'alt__tssh_cg', 'green.ssh.target', 'tssh______cg');

  insert into session
    (project_id,     target_id,      public_id,      user_id,        auth_token_id,  certificate,  endpoint)
             values
    ('p____bcolors', 'tssh______cb', 's1_____clare', 'u______clare', 'tok____clare', 'abc'::bytea, 'ep1'),
    ('p____bcolors', 't_________cb', 's1_____cindy', 'u______cindy', 'tok____cindy', 'abc'::bytea, 'ep1'),
    ('p____bcolors', 't_________cb', 's1_____ciara', 'u______cindy', 'tok____cindy', 'abc'::bytea, 'ep1'),
    ('p____bcolors', 't_________cb', 's1_____carly', 'u______carly', 'tok____carly', 'abc'::bytea, 'ep1'),
    ('p____gcolors', 'tssh______cg', 's1______cora', 'u_______cora', 'tok_____cora', 'abc'::bytea, 'ep1'),
    --- the next are used in recording_session tests
    ('p____bcolors', 'tssh______cb', 's2_____clare', 'u______clare', 'tok____clare', 'abc'::bytea, 'ep2'),
    ('p____gcolors', 'tssh______cg', 's2______cora', 'u_______cora', 'tok_____cora', 'abc'::bytea, 'ep3'),
    ('p____bcolors', 'tssh______cb', 's2_____carly', 'u______carly', 'tok____carly', 'abc'::bytea, 'ep4');

  insert into session_credential_static
    (session_id,     credential_static_id, credential_purpose)
  values
    ('s1_____clare', 'csj__bcolors',       'injected_application'), -- tssh______cb
    ('s2_____clare', 'csj__bcolors',       'injected_application'), -- tssh______cb
    ('s2_____carly', 'csj__bcolors',       'injected_application'), -- tssh______cb
    ('s1_____cindy', 'csj__bcolors',       'brokered'),             -- t_________cb
    ('s1_____ciara', 'csj__bcolors',       'brokered'),             -- t_________cb
    ('s1_____carly', 'csj__bcolors',       'brokered'),             -- t_________cb
    ('s1______cora', 'csj__gcolors',       'brokered'),             -- tssh______cg
    ('s1______cora', 'csu__gcolors',       'brokered'),             -- tssh______cg
    ('s1______cora', 'cspk_gcolors',       'injected_application'), -- tssh______cg
    ('s1______cora', 'csud_gcolors',       'brokered'),             -- tssh______cg
    ('s2______cora', 'csj__gcolors',       'brokered'),             -- tssh______cg
    ('s2______cora', 'cspk_gcolors',       'injected_application'); -- tssh______cg

  insert into session_credential_dynamic
    (session_id,     library_id,     credential_purpose)
  values
    ('s1______cora', 'cvl_______g1', 'brokered'),             -- tssh______cg
    ('s1______cora', 'cvl__ssh__g1', 'injected_application'); -- tssh______cg

  insert into session_host_set_host
    (session_id,     host_set_id,    host_id)
  values
    ('s1_____clare', 'hs__st____b1', 'h___st____b1'),
    ('s2_____clare', 'hs__st____b1', 'h___st____b1'),
    ('s1_____cindy', 'hs__st____b1', 'h___st____b1'),
    ('s1_____ciara', 'hs__st____b1', 'h___st____b1'),
    ('s1_____carly', 'hs__st____b1', 'h___st____b1'),
    ('s2_____carly', 'hs__plg___b1', 'h___plg___b1');

  insert into session_target_address
    (session_id,     target_id)
  values
    ('s1______cora', 't_________cg'),
    ('s2______cora', 't_________cg');

  insert into session_connection
    (session_id,     public_id)
  values
    ('s1_____clare', 's1c1___clare'),
    ('s2_____clare', 's2c1___clare');

  insert into recording_session
    (session_id,     storage_bucket_id, public_id,      target_org_id)
  values
    ('s1_____clare', 'sb____global',    'sr1____clare', 'o_____colors'),
    ('s1______cora', 'sb____colors',    'sr1_____cora', 'o_____colors');

commit;
