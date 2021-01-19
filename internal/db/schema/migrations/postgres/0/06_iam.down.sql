BEGIN;

drop table iam_group cascade;
drop table iam_user cascade;
drop table iam_scope_project cascade;
drop table iam_scope_org cascade;
drop table iam_scope_global cascade;
drop table iam_scope cascade;
drop table iam_scope_type_enm cascade;
drop table iam_role cascade;
drop view iam_principal_role cascade;
drop table iam_group_role cascade;
drop table iam_user_role cascade;
drop table iam_group_member_user cascade;
drop view iam_group_member cascade;
drop table iam_role_grant cascade;

drop function iam_sub_names cascade;
drop function iam_immutable_scope_type_func cascade;
drop function iam_sub_scopes_func cascade;
drop function iam_immutable_role_principal cascade;
drop function iam_user_role_scope_check cascade;
drop function iam_group_role_scope_check cascade;
drop function iam_group_member_scope_check cascade;
drop function iam_immutable_group_member cascade;
drop function get_scoped_member_id cascade;
drop function grant_scope_id_valid cascade;
drop function disallow_global_scope_deletion cascade;
drop function user_scope_id_valid cascade;
drop function iam_immutable_role_grant cascade;
drop function disallow_iam_predefined_user_deletion cascade;
drop function recovery_user_not_allowed cascade;

COMMIT;
