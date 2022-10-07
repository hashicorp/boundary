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
    ('key', 'apa______jim', 'tok______jim', 'tok______jim'::bytea),
    ('key', 'apa______bob', 'tok______bob', 'tok______bob'::bytea);

  -- Roles
  insert into iam_role
    (scope_id, grant_scope_id, public_id, name)
  values
    ('p______tacos', 'p______tacos', 'r_pp___tacos', 'Tacos');

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
    ( project_id,     target_id,      host_set_id,    host_id,        user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p______tacos', 't__________t', 's____1t-sths', 'h______t__01', 'u________jim', 'tok______jim', 'abc'::bytea, 'ep1',    's1_______jim');

commit;
