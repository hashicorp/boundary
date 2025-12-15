-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- iam_managed_group_role contains roles that have been assigned to managed
-- groups. Managed groups can be from any scope. The rows in this table must be
-- immutable after insert, which will be ensured with a before update trigger
-- using iam_immutable_role_principal().
create table iam_managed_group_role (
  create_time wt_timestamp,
  role_id wt_role_id
    references iam_role(public_id)
    on delete cascade
    on update cascade,
  principal_id wt_public_id 
    references auth_managed_group(public_id)
    on delete cascade
    on update cascade,
  primary key (role_id, principal_id)
  );

create trigger immutable_role_principal before update on iam_managed_group_role
  for each row execute procedure iam_immutable_role_principal();

create trigger default_create_time_column before insert on iam_managed_group_role
  for each row execute procedure default_create_time();

-- iam_principal_role provides a consolidated view all principal roles assigned
-- (user and group roles).
create or replace view iam_principal_role as
select
	ur.create_time,
	ur.principal_id,
	ur.role_id,
	u.scope_id as principal_scope_id,
	r.scope_id as role_scope_id,
	get_scoped_principal_id(r.scope_id, u.scope_id, ur.principal_id) as scoped_principal_id,
	'user' as type
from
	iam_user_role ur,
	iam_role r,
	iam_user u
where
	ur.role_id = r.public_id and
	u.public_id = ur.principal_id
union
select
	gr.create_time,
	gr.principal_id,
	gr.role_id,
	g.scope_id as principal_scope_id,
	r.scope_id as role_scope_id,
	get_scoped_principal_id(r.scope_id, g.scope_id, gr.principal_id) as scoped_principal_id,
	'group' as type
from
	iam_group_role gr,
	iam_role r,
	iam_group g
where
	gr.role_id = r.public_id and
	g.public_id = gr.principal_id
union
select
	mgr.create_time,
	mgr.principal_id,
	mgr.role_id,
	(select scope_id from auth_method am where am.public_id = amg.auth_method_id) as principal_scope_id,
	r.scope_id as role_scope_id,
	get_scoped_principal_id(r.scope_id, (select scope_id from auth_method am where am.public_id = amg.auth_method_id), mgr.principal_id) as scoped_principal_id,
	'managed group' as type
from
	iam_managed_group_role mgr,
	iam_role r,
	auth_managed_group amg
where
	mgr.role_id = r.public_id and
	amg.public_id = mgr.principal_id;

commit;
