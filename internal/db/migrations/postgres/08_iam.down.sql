BEGIN;

drop table if exists iam_auth_method cascade;
drop table if exists iam_group_member_type_enm cascade;
drop table if exists iam_group cascade cascade;
drop table if exists iam_group_member_user cascade;
drop view if exists iam_group_member;
drop table if exists iam_auth_method_type_enm cascade;
drop table if exists iam_action_enm cascade;
drop view if exists iam_assigned_role;


COMMIT;