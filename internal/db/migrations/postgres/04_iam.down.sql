BEGIN;

drop table iam_group cascade;
drop table iam_user cascade;
drop table iam_scope_project cascade;
drop table iam_scope_organization cascade;
drop table iam_scope cascade;
drop table iam_scope_type_enm cascade;

drop function iam_sub_names cascade;
drop function iam_immutable_scope_type_func cascade;
drop function iam_sub_scopes_func cascade;

COMMIT;
