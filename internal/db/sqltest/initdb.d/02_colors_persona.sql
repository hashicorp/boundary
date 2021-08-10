begin;
  -- _wtt_load_colors_iam populates all iam_ tables for the colors persona.
  -- iam does not depend on any other aggregates, but others depend on it,
  -- as such is it should be first in the list.
  create function _wtt_load_colors_iam()
    returns void
  as $$
  begin
    -- Add organizations
    insert into iam_scope
      (parent_id, type, public_id, name)
    values
      ('global', 'org', 'o_____colors', 'Colors R Us');

    -- Add projects to the organizations
    insert into iam_scope
      (parent_id, type, public_id, name)
    values
      ('o_____colors', 'project', 'p____bcolors', 'Blue Color Mill'),
      ('o_____colors', 'project', 'p____rcolors', 'Red Color Mill');

    -- Add global users
    insert into iam_user
      (scope_id, public_id, name)
    values
      ('global', 'u_______gary', 'Gary'),
      ('global', 'u_______gina', 'Gina'),
      ('global', 'u______nancy', 'Nancy');

    -- Add organization users
    insert into iam_user
      (scope_id, public_id, name)
    values
      ('o_____colors', 'u______clare', 'Clare'),
      ('o_____colors', 'u______cindy', 'Cindy'),
      ('o_____colors', 'u______carly', 'Carly'),
      ('o_____colors', 'u______ciara', 'Ciara');

    insert into iam_group
      (scope_id, public_id, name)
    values
      ('global',       'g___gg-group', 'Global Group'),
      ('o_____colors', 'g___oc-group', 'Colors R Us Group'),
      ('p____bcolors', 'g___cb-group', 'Blue Color Group'),
      ('p____rcolors', 'g___cr-group', 'Red Color Group');

    insert into iam_group_member_user
      (group_id, member_id)
    values
      ('g___gg-group', 'u_______gary'),
      ('g___oc-group', 'u______clare'),
      ('g___cb-group', 'u______cindy'),
      ('g___cr-group', 'u______carly');

    insert into iam_role
      (scope_id, grant_scope_id, public_id, name)
    values
      ('p____bcolors', 'p____bcolors', 'r_pp_bc__mix', 'Color Mixer'),
      ('p____rcolors', 'p____rcolors', 'r_pp_rc__mix', 'Color Mixer'),
      ('o_____colors', 'p____bcolors', 'r_op_bc__art', 'Blue Color Artist'),
      ('o_____colors', 'p____rcolors', 'r_op_rc__art', 'Red Color Artist'),
      ('o_____colors', 'o_____colors', 'r_oo_____art', 'Color Artist'),
            ('global', 'o_____colors', 'r_go____name', 'Color Namer'),
            ('global', 'p____bcolors', 'r_gp____spec', 'Blue Color Inspector'),
            ('global', 'global',       'r_gg_____buy', 'Purchaser'),
            ('global', 'global',       'r_gg____shop', 'Shopper');

    insert into iam_role_grant
      (role_id, canonical_grant, raw_grant)
    values
      ('r_gg_____buy', 'type=*;action=purchase',    'purchase anything'),
      ('r_gg____shop', 'type=*;action=view',        'view anything'),
      ('r_go____name', 'type=color;action=name',    'name colors'),
      ('r_gp____spec', 'type=color;action=inspect', 'inspect colors'),
      ('r_oo_____art', 'type=color;action=create',  'create color'),
      ('r_op_bc__art', 'type=color;action=create',  'create color'),
      ('r_op_rc__art', 'type=color;action=create',  'create color'),
      ('r_pp_bc__mix', 'type=color;action=mix',     'mix color'),
      ('r_pp_rc__mix', 'type=color;action=mix',     'mix color');

    insert into iam_group_role
      (role_id, principal_id)
    values
      ('r_op_rc__art', 'g___oc-group'), -- color
      ('r_pp_bc__mix', 'g___cb-group'), -- color
      ('r_pp_rc__mix', 'g___cr-group'); -- color

    insert into iam_user_role
      (role_id, principal_id)
    values
      ('r_go____name', 'u_______gary'),
      ('r_gp____spec', 'u_______gina'),
      ('r_gg_____buy', 'u_auth'),
      ('r_gg____shop', 'u_anon');
  end;
  $$ language plpgsql;

  -- _wtt_load_kms populates all kms_ tables for the colors persona.
  -- kms depends on iam.
  create function _wtt_load_colors_kms()
    returns void
  as $$
  begin
  end;
  $$ language plpgsql;

  -- _wtt_load_colors_auth populates all auth_ tables for the colors persona.
  -- auth depends on iam, and kms.
  create function _wtt_load_colors_auth()
    returns void
  as $$
  begin
    insert into auth_password_conf
      (password_method_id, private_id)
    values
      ('apm___colors', 'apmc__colors');


    -- Add password auth method to organizations
    insert into auth_password_method
      (scope_id, public_id, password_conf_id, name)
    values
      ('o_____colors', 'apm___colors', 'apmc__colors', 'Colors Auth Password');

    insert into auth_password_account
      (auth_method_id, public_id, login_name)
    values
      ('apm___colors', 'apa____clare', 'clare'),
      ('apm___colors', 'apa____cindy', 'cindy'),
      ('apm___colors', 'apa____carly', 'carly'),
      ('apm___colors', 'apa____ciara', 'ciara');

    update auth_account set iam_user_id = 'u______clare' where public_id = 'apa____clare';
    update auth_account set iam_user_id = 'u______cindy' where public_id = 'apa____cindy';
    update auth_account set iam_user_id = 'u______carly' where public_id = 'apa____carly';
    update auth_account set iam_user_id = 'u______ciara' where public_id = 'apa____ciara';

  end;
  $$ language plpgsql;

  -- _wtt_load_colors_hosts populates all host_ tables for the colors persona.
  -- hosts depend on iam.
  create function _wtt_load_colors_hosts()
    returns void
  as $$
  begin
    insert into static_host_catalog
      (scope_id, public_id, name)
    values
      ('p____bcolors', 'c___cb-sthcl', 'Blue Color Static Catalog'),
      ('p____rcolors', 'c___cr-sthcl', 'Red Color Static Catalog');

    insert into static_host
      (catalog_id, public_id, address)
    values
      ('c___cb-sthcl', 'h_____cb__01', '1.blue.color'),
      ('c___cb-sthcl', 'h_____cb__02', '2.blue.color'),
      ('c___cb-sthcl', 'h_____cb__03', '3.blue.color'),
      ('c___cb-sthcl', 'h_____cb__04', '4.blue.color'),
      ('c___cb-sthcl', 'h_____cb__05', '5.blue.color'),
      ('c___cb-sthcl', 'h_____cb__06', '6.blue.color'),
      ('c___cb-sthcl', 'h_____cb__07', '7.blue.color'),
      ('c___cb-sthcl', 'h_____cb__08', '8.blue.color'),
      ('c___cb-sthcl', 'h_____cb__09', '9.blue.color'),

      ('c___cr-sthcl', 'h_____cr__01', '1.red.color'),
      ('c___cr-sthcl', 'h_____cr__02', '2.red.color'),
      ('c___cr-sthcl', 'h_____cr__03', '3.red.color'),
      ('c___cr-sthcl', 'h_____cr__04', '4.red.color'),
      ('c___cr-sthcl', 'h_____cr__05', '5.red.color'),
      ('c___cr-sthcl', 'h_____cr__06', '6.red.color'),
      ('c___cr-sthcl', 'h_____cr__07', '7.red.color'),
      ('c___cr-sthcl', 'h_____cr__08', '8.red.color'),
      ('c___cr-sthcl', 'h_____cr__09', '9.red.color');

    insert into static_host_set
      (catalog_id, public_id, name)
    values
      ('c___cb-sthcl', 's___1cb-sths', 'Blue Color Static Set 1'),
      ('c___cb-sthcl', 's___2cb-sths', 'Blue Color Static Set 2'),
      ('c___cr-sthcl', 's___1cr-sths', 'Red Color Static Set 1'),
      ('c___cr-sthcl', 's___2cr-sths', 'Red Color Static Set 2');

    insert
      into static_host_set_member
           ( host_id,     set_id,      catalog_id)
    select h.public_id, s.public_id, s.catalog_id
      from static_host as h,
           static_host_set as s
     where h.catalog_id = s.catalog_id;
  end;
  $$ language plpgsql;

  -- _wtt_load_colors_targets populates all target_ tables for the colors persona.
  -- targets depend on iam, auth, hosts.
  create function _wtt_load_colors_targets()
    returns void
  as $$
  begin
    insert into target_tcp
      (scope_id, public_id, name)
    values
      ('p____bcolors', 't_________cb', 'Blue Color Target'),
      ('p____rcolors', 't_________cr', 'Red Color Target');

    insert into target_host_set
      (target_id, host_set_id)
    values
      ('t_________cb', 's___1cb-sths'),
      ('t_________cb', 's___2cb-sths'),
      ('t_________cr', 's___1cr-sths'),
      ('t_________cr', 's___2cr-sths');

  end;
  $$ language plpgsql;
commit;
