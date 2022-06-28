begin;
  -- _wtt_load_widgets_iam populates all iam_ tables for the widgets persona.
  -- iam does not depend on any other aggregates, but others depend on it,
  -- as such is it should be first in the list.
  create function _wtt_load_widgets_iam()
    returns void
  as $$
  begin
    -- Add organizations
    insert into iam_scope
      (parent_id, type, public_id, name)
    values
      ('global', 'org', 'o_____widget', 'Widget Inc');

    -- Add projects to the organizations
    insert into iam_scope
      (parent_id, type, public_id, name)
    values
      ('o_____widget', 'project', 'p____bwidget', 'Big Widget Factory'),
      ('o_____widget', 'project', 'p____swidget', 'Small Widget Factory');

    -- Add global users
    -- insert into iam_user
    --   (scope_id, public_id, name)
    -- values
    --   ('global', 'u_______gary', 'Gary'),
    --   ('global', 'u_______gina', 'Gina'),
    --   ('global', 'u______nancy', 'Nancy');

    -- Add organization users
    insert into iam_user
      (scope_id, public_id, name)
    values
      ('o_____widget', 'u_____walter', 'Walter'),
      ('o_____widget', 'u_____warren', 'Warren'),
      ('o_____widget', 'u_____waylon', 'Waylon'),
      ('o_____widget', 'u_____wilson', 'Wilson');

    insert into iam_group
      (scope_id, public_id, name)
    values
      -- ('global',       'g___gg-group', 'Global Group'),
      ('o_____widget', 'g___ow-group', 'Widget Inc Group'),
      ('p____bwidget', 'g___wb-group', 'Big Widget Group'),
      ('p____swidget', 'g___ws-group', 'Small Widget Group');

    insert into iam_group_member_user
      (group_id, member_id)
    values
      -- ('g___gg-group', 'u_______gary'),
      ('g___ow-group', 'u_____walter'),
      ('g___wb-group', 'u_____warren'),
      ('g___ws-group', 'u_____waylon');

    insert into iam_role
      (scope_id, grant_scope_id, public_id, name)
    values
            -- ('global', 'global',       'r_gg_____buy', 'Purchaser'),
            -- ('global', 'global',       'r_gg____shop', 'Shopper'),
      ('p____bwidget', 'p____bwidget', 'r_pp_bw__bld', 'Widget Builder'),
      ('p____swidget', 'p____swidget', 'r_pp_sw__bld', 'Widget Builder'),
      ('o_____widget', 'p____swidget', 'r_op_sw__eng', 'Small Widget Engineer'),
      ('o_____widget', 'o_____widget', 'r_oo_____eng', 'Widget Engineer');

    insert into iam_role_grant
      (role_id, canonical_grant, raw_grant)
    values
      -- ('r_gg_____buy', 'type=*;action=purchase',    'purchase anything'),
      -- ('r_gg____shop', 'type=*;action=view',        'view anything'),
      ('r_oo_____eng', 'type=widget;action=design', 'design widget'),
      ('r_op_sw__eng', 'type=widget;action=design', 'design widget'),
      ('r_op_sw__eng', 'type=widget;action=tune',   'tune widget'),
      ('r_op_sw__eng', 'type=widget;action=clean',  'clean widget'),
      ('r_pp_bw__bld', 'type=widget;action=build',  'build widget'),
      ('r_pp_sw__bld', 'type=widget;action=build',  'build widget');

    insert into iam_group_role
      (role_id, principal_id)
    values
      ('r_oo_____eng', 'g___ow-group'), -- widget
      ('r_pp_bw__bld', 'g___wb-group'), -- widget
      ('r_pp_sw__bld', 'g___ws-group'); -- widget

    -- insert into iam_user_role
    --   (role_id, principal_id)
    -- values
    --   ('r_gg_____buy', 'u_auth'),
    --   ('r_gg____shop', 'u_anon');
  end;
  $$ language plpgsql;

  -- _wtt_load_kms populates all kms_ tables for the widgets persona.
  -- kms depends on iam.
  create function _wtt_load_widgets_kms()
    returns void
  as $$
  begin
    insert into kms_root_key
      (private_id,     scope_id)
    values
      ('krk___widget', 'o_____widget');

    insert into kms_root_key_version
      (private_id,      root_key_id,    key)
    values
      ('krkv___widget', 'krk___widget', 'krk___widget'::bytea);

    insert into kms_data_key
      (private_id, root_key_id, purpose)
    values
      ('kdk____widget', 'krk___widget', 'database');

    insert into kms_data_key_version
      (private_id,      data_key_id, root_key_version_id, key)
    values
      ('kdkv___widget', 'kdk____widget', 'krkv___widget',     'kdk____widget'::bytea);

  end;
  $$ language plpgsql;

  -- _wtt_load_widgets_auth populates all auth_ tables for the widgets persona.
  -- auth depends on iam, and kms.
  create function _wtt_load_widgets_auth()
    returns void
  as $$
  begin
    insert into auth_password_conf
      (password_method_id, private_id)
    values
      ('apm___widget', 'apmc__widget'),
      ('apm1__widget', 'apmc1_widget');


    -- Add password auth method to organizations
    insert into auth_password_method
      (scope_id, public_id, password_conf_id, name)
    values
      ('o_____widget', 'apm___widget', 'apmc__widget', 'Widget Auth Password'),
      ('o_____widget', 'apm1__widget', 'apmc1_widget', 'Widget Auth Password 1');

    insert into auth_password_account
      (auth_method_id, public_id, login_name)
    values
      ('apm___widget', 'apa___walter', 'walter'),
      ('apm1__widget', 'apa1__walter', 'walter'),
      ('apm___widget', 'apa___warren', 'warren'),
      ('apm___widget', 'apa___waylon', 'waylon'),
      ('apm___widget', 'apa___wilson', 'wilson');

    update auth_account set iam_user_id = 'u_____walter' where public_id = 'apa___walter';
    update auth_account set iam_user_id = 'u_____walter' where public_id = 'apa1__walter';
    update auth_account set iam_user_id = 'u_____warren' where public_id = 'apa___warren';
    update auth_account set iam_user_id = 'u_____waylon' where public_id = 'apa___waylon';
    update auth_account set iam_user_id = 'u_____wilson' where public_id = 'apa___wilson';

    insert into auth_token
      (key_id, auth_account_id, public_id, token)
    values
      ('key', 'apa___walter', 'tok___walter', 'tok___walter'::bytea),
      ('key', 'apa1__walter', 'tok1__walter', 'tok1__walter'::bytea),
      ('key', 'apa___warren', 'tok___warren', 'tok___warren'::bytea),
      ('key', 'apa___waylon', 'tok___waylon', 'tok___waylon'::bytea),
      ('key', 'apa___wilson', 'tok___wilson', 'tok___wilson'::bytea);

    insert into auth_oidc_method
      (scope_id,       public_id,      client_id,      name,          state,            key_id,          issuer)
    values
      ('o_____widget', 'aom___widget', 'aomc__widget', 'Widget OIDC', 'active-private', 'kdkv___widget', 'https://oidc.widget.test');

    insert into auth_oidc_account
      (auth_method_id, public_id,      name,             description,           full_name, email,                issuer,                subject)
    values
      ('aom___widget', 'aoa___walter', 'walter account', 'Walter OIDC Account', 'Walter',  'walter@widget.test', 'https://widget.test', 'sub___walter'),
      ('aom___widget', 'aoa___warren', 'warren account', 'Warren OIDC Account', null,      null,                 'https://widget.test', 'sub___warren');

    update auth_account set iam_user_id = 'u_____walter' where public_id = 'aoa___walter';
    update auth_account set iam_user_id = 'u_____warren' where public_id = 'aoa___warren';

    insert into auth_token
      (key_id, auth_account_id, public_id, token)
    values
      ('key', 'aoa___walter', 'oidc__walter', 'oidc__walter'::bytea),
      ('key', 'aoa___warren', 'oidc__warren', 'oidc__warren'::bytea);

  end;
  $$ language plpgsql;

  -- _wtt_load_widgets_hosts populates all host_ tables for the widgets persona.
  -- hosts depend on iam.
  create function _wtt_load_widgets_hosts()
    returns void
  as $$
  begin
    insert into static_host_catalog
      (scope_id, public_id, name)
    values
      ('p____bwidget', 'c___wb-sthcl', 'Big Widget Static Catalog'),
      ('p____swidget', 'c___ws-sthcl', 'Small Widget Static Catalog');

    insert into static_host
      (catalog_id, public_id, address)
    values
      ('c___wb-sthcl', 'h_____wb__01', '1.big.widget'),
      ('c___wb-sthcl', 'h_____wb__02', '2.big.widget'),
      ('c___wb-sthcl', 'h_____wb__03', '3.big.widget'),
      ('c___wb-sthcl', 'h_____wb__04', '4.big.widget'),
      ('c___wb-sthcl', 'h_____wb__05', '5.big.widget'),
      ('c___wb-sthcl', 'h_____wb__06', '6.big.widget'),
      ('c___wb-sthcl', 'h_____wb__07', '7.big.widget'),
      ('c___wb-sthcl', 'h_____wb__08', '8.big.widget'),
      ('c___wb-sthcl', 'h_____wb__09', '9.big.widget'),

      ('c___ws-sthcl', 'h_____ws__01', '1.small.widget'),
      ('c___ws-sthcl', 'h_____ws__02', '2.small.widget'),
      ('c___ws-sthcl', 'h_____ws__03', '3.small.widget'),
      ('c___ws-sthcl', 'h_____ws__04', '4.small.widget'),
      ('c___ws-sthcl', 'h_____ws__05', '5.small.widget'),
      ('c___ws-sthcl', 'h_____ws__06', '6.small.widget'),
      ('c___ws-sthcl', 'h_____ws__07', '7.small.widget'),
      ('c___ws-sthcl', 'h_____ws__08', '8.small.widget'),
      ('c___ws-sthcl', 'h_____ws__09', '9.small.widget');

    insert into static_host_set
      (catalog_id, public_id, name)
    values
      ('c___wb-sthcl', 's___1wb-sths', 'Big Widget Static Set 1'),
      ('c___wb-sthcl', 's___2wb-sths', 'Big Widget Static Set 2'),
      ('c___ws-sthcl', 's___1ws-sths', 'Small Widget Static Set 1'),
      ('c___ws-sthcl', 's___2ws-sths', 'Small Widget Static Set 2');

    insert
      into static_host_set_member
           ( host_id,     set_id,      catalog_id)
    select h.public_id, s.public_id, s.catalog_id
      from static_host as h,
           static_host_set as s
     where h.catalog_id = s.catalog_id
       and h.address like '%.widget';

    insert into plugin_host
      (scope_id, public_id, name)
    values
      ('global', 'plg___wb-hplg', 'Short Host Plugin');

    insert into host_plugin_catalog
      (scope_id, public_id, plugin_id, name, attributes)
    values
      ('p____bwidget', 'c___wb-plghcl', 'plg___wb-hplg', 'Big Widget Plugin Catalog', ''),
      ('p____swidget', 'c___ws-plghcl', 'plg___wb-hplg',  'Small Widget Plugin Catalog', '');

    insert into host_plugin_host
      (catalog_id, public_id, external_id)
    values
      ('c___wb-plghcl', 'h_____wb__01-plgh', '1 big widget'),
      ('c___wb-plghcl', 'h_____wb__02-plgh', '2 big widget'),
      ('c___wb-plghcl', 'h_____wb__03-plgh', '3 big widget'),

      ('c___ws-plghcl', 'h_____ws__01-plgh', '1 small widget'),
      ('c___ws-plghcl', 'h_____ws__02-plgh', '2 small widget'),
      ('c___ws-plghcl', 'h_____ws__03-plgh', '3 small widget');

    insert into host_dns_name
    (host_id, name)
    values
      ('h_____wb__01-plgh', '1.big.widget'),
      ('h_____wb__02-plgh', '2.big.widget'),
      ('h_____wb__03-plgh', '3.big.widget'),

      ('h_____ws__01-plgh', '1.small.widget'),
      ('h_____ws__02-plgh', '2.small.widget'),
      ('h_____ws__03-plgh', '3.small.widget');

    insert into host_ip_address
    (host_id, address)
    values
      ('h_____wb__01-plgh', '1.1.1.1'),
      ('h_____wb__02-plgh', 'fe80::2222:2222:2222:2222'),
      -- host 3 only has a dns name so the set of addresses are the same
      -- between the static and plugin based host

      ('h_____ws__01-plgh', '11.11.11.11'),
      ('h_____ws__02-plgh', '2001:4860:4860::2222'),
      ('h_____ws__03-plgh', '33.33.33.33');

    insert into host_plugin_set
      (catalog_id, public_id, name, attributes, need_sync)
    values
      ('c___wb-plghcl', 's___1wb-plghs', 'Big Widget Plugin Set 1', '', false),
      ('c___wb-plghcl', 's___2wb-plghs', 'Big Widget Plugin Set 2', '', false),
      ('c___ws-plghcl', 's___1ws-plghs', 'Small Widget Plugin Set 1', '', false),
      ('c___ws-plghcl', 's___2ws-plghs', 'Small Widget Plugin Set 2', '', false);

    insert
      into host_plugin_set_member
           ( host_id,     set_id,      catalog_id)
    select h.public_id, s.public_id, s.catalog_id
      from host_plugin_host as h,
           host_plugin_set as s
     where h.catalog_id = s.catalog_id;
  end;
  $$ language plpgsql;

  -- _wtt_load_widgets_targets populates all target_ tables for the widgets persona.
  -- targets depend on iam, auth, hosts.
  create function _wtt_load_widgets_targets()
    returns void
  as $$
  begin
    insert into target_tcp
      (scope_id, public_id, name)
    values
      ('p____bwidget', 't_________wb', 'Big Widget Target'),
      ('p____swidget', 't_________ws', 'Small Widget Target');

    insert into target_host_set
      (target_id, host_set_id)
    values
      ('t_________wb', 's___1wb-sths'),
      ('t_________wb', 's___2wb-sths'),
      ('t_________ws', 's___1ws-sths'),
      ('t_________ws', 's___2ws-sths'),
      ('t_________wb', 's___1wb-plghs'),
      ('t_________wb', 's___2wb-plghs'),
      ('t_________ws', 's___1ws-plghs'),
      ('t_________ws', 's___2ws-plghs');

  end;
  $$ language plpgsql;

  create function _wtt_load_widgets_credentials()
    returns void
  as $$
  begin
    insert into credential_vault_store
      (scope_id,       public_id,      name,                 description, vault_address,          namespace)
    values
      ('p____bwidget', 'vs_______wvs', 'widget vault store', 'None',      'https://vault.widget', 'default');

    insert into credential_vault_token
      (store_id,       key_id,          status,   token_hmac,   token,         last_renewal_time, expiration_time)
    values
      ('vs_______wvs', 'kdkv___widget', 'current', 'hmac-value', 'token-value', now(),             now() + interval '1 hour');

    insert into credential_vault_library
      (store_id,       public_id,      name,                    description, vault_path,           http_method, credential_type)
    values
      ('vs_______wvs', 'vl______wvl1', 'widget vault library',  'None',      '/secrets',           'GET',       'unspecified'),
      ('vs_______wvs', 'vl______wvl2', 'widget vault ssh',      'None',      '/secrets/ssh/admin', 'GET',       'unspecified'),
      ('vs_______wvs', 'vl______wvl3', 'widget vault kv one',   'None',      '/secrets/kv/one',    'GET',       'username_password'),
      ('vs_______wvs', 'vl______wvl4', 'widget vault kv two',   'None',      '/secrets/kv/two',    'GET',       'username_password'),
      ('vs_______wvs', 'vl______wvl5', 'widget vault kv three', 'None',      '/secrets/kv/three',  'GET',       'username_password'),
      ('vs_______wvs', 'vl______wvl6', 'widget vault kv four',  'None',      '/secrets/kv/four',   'GET',       'username_password'),
      ('vs_______wvs', 'vl______wvl7', 'widget vault kv five',  'None',      '/secrets/kv/five',   'GET',       'username_password');

    insert into credential_vault_library_username_password_mapping_override
      (library_id)
    values
      ('vl______wvl4');

    insert into credential_vault_library_username_password_mapping_override
      (library_id,     username_attribute)
    values
      ('vl______wvl5', 'my_username');

    insert into credential_vault_library_username_password_mapping_override
      (library_id,     password_attribute)
    values
      ('vl______wvl6', 'my_password');

    insert into credential_vault_library_username_password_mapping_override
      (library_id,     username_attribute, password_attribute)
    values
      ('vl______wvl7', 'my_username',      'my_password');

    insert into target_credential_library
      (target_id,      credential_library_id, credential_purpose)
    values
      ('t_________wb', 'vl______wvl1',        'application'),
      ('t_________wb', 'vl______wvl2',        'application'),
      ('t_________wb', 'vl______wvl3',        'application'),
      ('t_________wb', 'vl______wvl3',        'egress');
  end;
  $$ language plpgsql;

create function _wtt_load_widgets_sessions()
    returns void
as $$
begin
    insert into session
    ( scope_id      , target_id      , host_set_id    , host_id        , user_id        , auth_token_id  , certificate  , endpoint , public_id)
    values
        ('p____bwidget' , 't_________wb' , 's___1wb-sths' , 'h_____wb__01' , 'u_____warren' , 'tok___warren' , 'abc'::bytea , 'ep1'    , 's1____warren');
end;
$$ language plpgsql;

commit;
