BEGIN;

drop table if exists iam_scope CASCADE;
drop trigger if exists iam_scope_insert;
drop function if exists iam_sub_scopes_func;
drop table if exists iam_auth_method cascade;
drop table if exists  iam_role cascade;
drop table if exists iam_group_member_type_enm cascade;
drop table if exists iam_group cascade cascade;
drop table if exists iam_group_member_user cascade;
drop view if exists iam_group_member;
drop table if exists iam_auth_method_type_enm cascade;
drop table if exists iam_action_enm cascade;
drop table if exists iam_role_type_enm cascade;
drop table if exists iam_role_user cascade;
drop table if exists iam_role_group cascade;
drop table if exists iam_role_grant cascade;
drop view if exists iam_assigned_role;


COMMIT;