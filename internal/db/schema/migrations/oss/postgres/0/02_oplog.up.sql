-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- TODO (jimlambrt 7/2020) remove update_time
create table if not exists oplog_entry (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version text not null,
  aggregate_name text not null,
  "data" bytea not null
);

create trigger update_time_column before update on oplog_entry
  for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on oplog_entry
  for each row execute procedure default_create_time();

-- oplog_entry is immutable.
create trigger immutable_columns before update on oplog_entry
  for each row execute procedure immutable_columns('id','update_time','create_time','version','aggregate_name', 'data');

create table if not exists oplog_ticket (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  "name" text not null unique,
  "version" bigint not null
);

create trigger update_time_column before update on oplog_ticket
  for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on oplog_ticket
  for each row execute procedure default_create_time();

-- oplog_ticket: only allow updates to: version and update_time
create trigger immutable_columns before update on oplog_ticket
  for each row execute procedure immutable_columns('id','create_time','name');
  
-- TODO (jimlambrt 7/2020) remove update_time
create table if not exists oplog_metadata (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  entry_id bigint not null
    references oplog_entry(id)
    on delete cascade
    on update cascade,
  "key" text not null,
  value text null
);

create trigger update_time_column before update on oplog_metadata
  for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on oplog_metadata
  for each row execute procedure default_create_time();

 -- oplog_metadata is immutable
create trigger immutable_columns before update on oplog_metadata
  for each row execute procedure immutable_columns('id','create_time','update_time','entry_id','key','value');

create index if not exists idx_oplog_metatadata_key on oplog_metadata(key);

create index if not exists idx_oplog_metatadata_value on oplog_metadata(value);

insert into oplog_ticket (name, version)
values
  ('auth_token', 1),
  ('default', 1),
  ('iam_scope', 1),
  ('iam_user', 1),
  ('iam_group', 1),
  ('iam_group_member', 1),
  ('iam_role', 1),
  ('iam_role_grant', 1),
  ('iam_group_role', 1),
  ('iam_user_role', 1),
  ('db_test_user', 1),
  ('db_test_car', 1),
  ('db_test_rental', 1),
  ('db_test_scooter', 1),
  ('auth_account', 1),
  ('iam_principal_role', 1);
  

commit;

