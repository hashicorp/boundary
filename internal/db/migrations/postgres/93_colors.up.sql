begin;
  insert into iam_scope
    (parent_id, type, public_id, name)
  values
    ('global', 'org', 'o_____widget', 'Widget Inc'),
    ('global', 'org', 'o_____colors', 'Colors R Us');

  insert into iam_user
    (scope_id, public_id, name)
  values
    ('global', 'u_______gary', 'Gary'),
    ('global', 'u_______gina', 'Gina');

  insert into iam_scope
    (parent_id, type, public_id, name)
  values
    ('o_____widget', 'project', 'p____bwidget', 'Big Widget Factory'),
    ('o_____widget', 'project', 'p____swidget', 'Small Widget Factory'),
    ('o_____colors', 'project', 'p____bcolors', 'Blue Color Mill'),
    ('o_____colors', 'project', 'p____rcolors', 'Red Color Mill');

  insert into iam_user
    (scope_id, public_id, name)
  values
    ('o_____widget', 'u_____walter', 'Walter'),
    ('o_____widget', 'u_____warren', 'Warren'),
    ('o_____widget', 'u_____waylon', 'Waylon'),
    ('o_____widget', 'u_____wilson', 'Wilson'),
    ('o_____colors', 'u______clare', 'Clare'),
    ('o_____colors', 'u______cindy', 'Cindy'),
    ('o_____colors', 'u______carly', 'Carly'),
    ('o_____colors', 'u______ciara', 'Ciara');

  insert into iam_group
    (scope_id, public_id, name)
  values
    ('global',       'g___gg-group', 'Global Group'),
    ('o_____widget', 'g___ow-group', 'Widget Inc Group'),
    ('o_____colors', 'g___oc-group', 'Colors R Us Group'),
    ('p____bwidget', 'g___wb-group', 'Big Widget Group'),
    ('p____swidget', 'g___ws-group', 'Small Widget Group'),
    ('p____bcolors', 'g___cb-group', 'Blue Color Group'),
    ('p____rcolors', 'g___cr-group', 'Red Color Group');


  insert into iam_group_member_user
    (group_id, member_id)
  values
    ('g___gg-group', 'u_______gary'),
    ('g___oc-group', 'u______clare'),
    ('g___cb-group', 'u______cindy'),
    ('g___cr-group', 'u______carly'),
    ('g___ow-group', 'u_____walter'),
    ('g___wb-group', 'u_____warren'),
    ('g___ws-group', 'u_____waylon');

  insert into iam_role
    (scope_id, grant_scope_id, public_id, name)
  values
    ('p____bwidget', 'p____bwidget', 'r_pp_bw__bld', 'Widget Builder'),
    ('p____swidget', 'p____swidget', 'r_pp_sw__bld', 'Widget Builder'),
    ('p____bcolors', 'p____bcolors', 'r_pp_bc__mix', 'Color Mixer'),
    ('p____rcolors', 'p____rcolors', 'r_pp_rc__mix', 'Color Mixer'),
    ('o_____widget', 'p____bwidget', 'r_pp_bw__eng', 'Big Widget Engineer'),
    ('o_____widget', 'p____swidget', 'r_op_sw__eng', 'Small Widget Engineer'),
    ('o_____colors', 'p____bcolors', 'r_op_bc__art', 'Blue Color Artist'),
    ('o_____colors', 'p____rcolors', 'r_op_rc__art', 'Red Color Artist'),
    ('o_____widget', 'o_____widget', 'r_oo_____eng', 'Widget Engineer'),
    ('o_____colors', 'o_____colors', 'r_oo_____art', 'Color Artist'),
          ('global', 'o_____colors', 'r_go____name', 'Color Namer'),
          ('global', 'p____bcolors', 'r_gp____spec', 'Blue Color Inspector'),
          ('global', 'global',       'r_gg_____buy', 'Consumer');


  insert into iam_role_grant
    (role_id, canonical_grant, raw_grant)
  values
    ('r_gg_____buy', 'type=*;action=purchase', 'purchase anything'),
    ('r_go____name', 'type=color;action=name', 'name colors'),
    ('r_gp____spec', 'type=color;action=inspect', 'inspect colors'),
    ('r_oo_____art', 'type=color;action=create', 'create color'),
    ('r_op_bc__art', 'type=color;action=create', 'create color'),
    ('r_op_rc__art', 'type=color;action=create', 'create color'),
    ('r_pp_bc__mix', 'type=color;action=mix', 'mix color'),
    ('r_pp_rc__mix', 'type=color;action=mix', 'mix color'),
    ('r_oo_____eng', 'type=widget;action=design', 'design widget'),
    ('r_op_sw__eng', 'type=widget;action=design', 'design widget'),
    ('r_pp_bw__eng', 'type=widget;action=design', 'design widget'),
    ('r_pp_bw__bld', 'type=widget;action=build', 'build widget'),
    ('r_pp_sw__bld', 'type=widget;action=build', 'build widget');

  insert into iam_group_role
    (role_id, principal_id)
  values
    ('r_gg_____buy', 'g___gg-group'),
    ('r_oo_____eng', 'g___ow-group'), -- widget
    ('r_pp_bw__bld', 'g___wb-group'), -- widget
    ('r_pp_sw__bld', 'g___ws-group'), -- widget
    ('r_op_rc__art', 'g___oc-group'), -- color
    ('r_pp_bc__mix', 'g___cb-group'), -- color
    ('r_pp_rc__mix', 'g___cr-group'); -- color

  insert into iam_user_role
    (role_id, principal_id)
  values
    ('r_pp_bw__eng', 'u______carly'),
    ('r_op_sw__eng', 'u______cindy'),
    ('r_op_bc__art', 'u_____waylon'),
    ('r_oo_____art', 'u_____warren'),
    ('r_go____name', 'u_______gary'),
    ('r_gp____spec', 'u_______gina'),
    ('r_gg_____buy', 'u_anon');

commit;
