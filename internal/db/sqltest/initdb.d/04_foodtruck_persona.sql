-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- This persona is setup primary to test a delete org case

  -- Add organizations
  insert into iam_scope
    (parent_id, type,  public_id,      name)
  values
    ('global',  'org', 'o__foodtruck', 'Best Tacos');

  -- Add projects to the organizations
  insert into iam_scope
    (parent_id,      type,      public_id,      name)
  values
    ('o__foodtruck', 'project', 'p______tacos', 'Tacos'),
    ('o__foodtruck', 'project', 'p_____nachos', 'Nachos');

  -- KMS

  insert into kms_root_key
    (private_id,         scope_id)
  values
    ('krk___foodtruck', 'o__foodtruck');

  insert into kms_root_key_version
    (private_id,         root_key_id,       key)
  values
    ('krkv___foodtruck', 'krk___foodtruck', 'krk___foodtruck'::bytea);

  insert into kms_data_key
    (private_id,         root_key_id,        purpose)
  values
    ('kdk____foodtruck', 'krk___foodtruck', 'database');

  insert into kms_data_key_version
    (private_id,         data_key_id,        root_key_version_id, key)
  values
    ('kdkv___foodtruck', 'kdk____foodtruck', 'krkv___foodtruck',  'kdk____foodtruck'::bytea);

  -- Host Catalog, Host, Host Set
  insert into static_host_catalog
    (project_id,     public_id,      name)
  values
    ('p______tacos', 'c____t-sthcl', 'Tacos Food Truck Static Catalog');

  insert into static_host
    (catalog_id,     public_id,      address)
  values
    ('c____t-sthcl', 'h______t__01', '1.taco.foodtruck');

  insert into static_host_set
    (catalog_id,     public_id,      name)
  values
    ('c____t-sthcl', 's____1t-sths', 'Taco Food Truck Static Set 1');

  insert into static_host_set_member
    ( host_id,        set_id,         catalog_id)
  values
    ( 'h______t__01', 's____1t-sths', 'c____t-sthcl');

  -- Target
  insert into target_tcp
    (project_id, public_id, name)
  values
    ('p______tacos', 't__________t', 'Taco Food Truck Target');

  insert into target_host_set
    (project_id,     target_id,      host_set_id)
  values
    ('p______tacos', 't__________t', 's____1t-sths');

  -- Add password auth method to organizations
  insert into auth_password_conf
    (password_method_id, private_id)
  values
    ('apm_foodtruc', 'apmc_foodtru');

  -- Auth method and account
  insert into auth_password_method
    (scope_id, public_id, password_conf_id, name)
  values
    ('o__foodtruck', 'apm_foodtruc', 'apmc_foodtru', 'Food Truck Auth Password');

  insert into auth_password_account
    (auth_method_id, public_id, login_name)
  values
    ('apm_foodtruc', 'apa______jim', 'jim'),
    ('apm_foodtruc', 'apa______bob', 'bob');

  -- Add organization users
  insert into iam_user
    (scope_id,       public_id,      name)
  values
    ('o__foodtruck', 'u________jim', 'Jim'),
    ('o__foodtruck', 'u________bob', 'Bob');

  update auth_account set iam_user_id = 'u________jim' where public_id = 'apa______jim';
  update auth_account set iam_user_id = 'u________bob' where public_id = 'apa______bob';

  insert into auth_token
    (key_id, auth_account_id, public_id, token)
  values
    ('kdkv___foodtruck', 'apa______jim', 'tok______jim', 'tok______jim'::bytea),
    ('kdkv___foodtruck', 'apa______bob', 'tok______bob', 'tok______bob'::bytea);

  -- Roles
  insert into iam_role_project
    (scope_id, public_id, name, grant_this_role_scope)
  values
    ('p______tacos', 'r_pp___tacos', 'Tacos', true);

  insert into iam_role_grant
    (role_id,        canonical_grant,                              raw_grant)
  values
    ('r_pp___tacos', 'id=*;type=*;actions=read:self,list',         'id=*;type=*;actions=read:self,list'),
    ('r_pp___tacos', 'id=*;type=target;actions=authorize-session', 'id=*;type=target;actions=authorize-session'),
    ('r_pp___tacos', 'id=*;type=session;actions=cancel:self',      'id=*;type=session;actions=cancel:self');

  insert into iam_user_role
    (role_id,        principal_id)
  values
    ('r_pp___tacos', 'u________jim'),
    ('r_pp___tacos', 'u________bob');

  insert into session
    ( project_id,     target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p______tacos', 't__________t', 'u________jim', 'tok______jim', 'abc'::bytea, 'ep1',    's1_______jim');

  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1_______jim', 's____1t-sths', 'h______t__01');

commit;
