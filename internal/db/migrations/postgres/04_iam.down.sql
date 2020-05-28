BEGIN;

drop table if exists iam_scope CASCADE;
drop trigger if exists iam_scope_insert;
drop function if exists iam_sub_scopes_func;

drop trigger if exists update_iam_scope_update_time on iam_scope;
drop trigger if exists update_iam_scope_create_time on iam_scope;

COMMIT;