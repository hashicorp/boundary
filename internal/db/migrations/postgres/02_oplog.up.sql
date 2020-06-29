begin;

create table if not exists oplog_entry (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version text not null,
  aggregate_name text not null,
  "data" bytea not null
);

create trigger 
  update_time_column 
before 
update on oplog_entry 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on oplog_entry 
  for each row execute procedure immutable_create_time_func();

create trigger 
  default_create_time_column
before
insert on oplog_entry
  for each row execute procedure default_create_time();

create table if not exists oplog_ticket (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  "name" text not null unique,
  "version" bigint not null
);

create trigger 
  update_time_column 
before 
update on oplog_ticket 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on oplog_ticket 
  for each row execute procedure immutable_create_time_func();

create trigger 
  default_create_time_column
before
insert on oplog_ticket
  for each row execute procedure default_create_time();

create table if not exists oplog_metadata (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  entry_id bigint not null references oplog_entry(id) on delete cascade on update cascade,
  "key" text not null,
  value text null
);

create trigger 
  update_time_column 
before 
update on oplog_metadata 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on oplog_metadata 
  for each row execute procedure immutable_create_time_func();

create trigger 
  default_create_time_column
before
insert on oplog_metadata 
  for each row execute procedure default_create_time();

create index if not exists idx_oplog_metatadata_key on oplog_metadata(key);

create index if not exists idx_oplog_metatadata_value on oplog_metadata(value);

insert into oplog_ticket (name, version)
values
  ('default', 1),
  ('iam_scope', 1),
  ('iam_user', 1),
  ('iam_group', 1),
  ('iam_group_member_user', 1),
  ('iam_role', 1),
  ('iam_role_grant', 1),
  ('iam_group_role', 1),
  ('iam_user_role', 1),
  ('db_test_user', 1),
  ('db_test_car', 1),
  ('db_test_rental', 1),
  ('db_test_scooter', 1),
  ('auth_account', 1);
;
  

commit;

