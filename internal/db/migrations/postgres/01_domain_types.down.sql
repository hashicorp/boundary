begin;

drop domain wt_timestamp;
drop domain wt_public_id;
drop domain wt_private_id;
drop function update_time_column() cascade;
drop function immutable_create_time_func() cascade;
commit;
