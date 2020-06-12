BEGIN;

drop table if exists iam_scope CASCADE;
drop table if exists iam_user cascade;
drop table if exists iam_group cascade;

drop function iam_sub_scopes_func cascade;
drop function iam_immutable_scope_type_func cascade;
drop function iam_sub_names cascade;

COMMIT;