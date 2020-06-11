BEGIN;

drop table if exists iam_scope CASCADE;
drop trigger if exists iam_scope_insert;
drop function if exists iam_sub_scopes_func;
drop table if exists iam_user cascade;
drop table if exists iam_role cascade;
drop function iam_sub_scopes_func cascade;

-- TODO: we cannot "drop function update_time_column cascade" since it will
-- affect more that this migration.  It would delete any table in any migration
-- that depends on it.  We need to move this drop function up to the 01
-- migration, so it's at the top level.  Need to discuss with mgaffney

drop trigger if exists update_iam_scope_update_time on iam_scope;
drop trigger if exists update_iam_scope_create_time on iam_scope;

COMMIT;