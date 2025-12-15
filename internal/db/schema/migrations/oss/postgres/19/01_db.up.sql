-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table if not exists db_test_accessory (
  accessory_id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  description text not null
);

create trigger update_time_column before update on db_test_accessory
  for each row execute procedure update_time_column();

create trigger immutable_columns before update on db_test_accessory
  for each row execute procedure immutable_columns('create_time');

create trigger default_create_time_column before insert on db_test_accessory
  for each row execute procedure default_create_time();

create table if not exists db_test_scooter_accessory (
  accessory_id bigint references db_test_accessory(accessory_id),
  scooter_id bigint references db_test_scooter(id),
  create_time wt_timestamp,
  update_time wt_timestamp,
  review text,
  primary key(accessory_id, scooter_id)
);

create trigger update_time_column before update on db_test_scooter_accessory
  for each row execute procedure update_time_column();

create trigger immutable_columns before update on db_test_scooter_accessory
  for each row execute procedure immutable_columns('create_time');

create trigger default_create_time_column before insert on db_test_scooter_accessory
  for each row execute procedure default_create_time();

commit;
