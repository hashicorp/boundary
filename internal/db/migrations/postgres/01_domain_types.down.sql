begin;

drop domain wt_timestamp;
drop domain wt_public_id;
drop domain wt_private_id;
drop domain wt_scope_id;
drop domain wt_user_id;
drop domain wt_version;

drop function default_create_time;
drop function update_time_column;
drop function update_version_column;
drop function immutable_columns;

commit;
