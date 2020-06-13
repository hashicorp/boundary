begin;

drop domain wt_timestamp;
drop domain wt_public_id;

drop function default_create_time;
drop function immutable_create_time_func;
drop function update_time_column;

commit;
