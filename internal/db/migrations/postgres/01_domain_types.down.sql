begin;

drop domain wt_timestamp;
drop domain wt_public_id;
drop domain wt_version;

drop function default_create_time;
drop function immutable_create_time_func;
drop function update_time_column;
drop function update_version_column;

commit;
