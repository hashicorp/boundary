-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- create test tables used in the unit tests for the internal/db package 
-- these tables (db_test_user, db_test_car, db_test_rental, db_test_scooter) are
-- not part of the boundary domain model... they are simply used for testing
-- the internal/db package 
create table if not exists db_test_user (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  phone_number text,
  email text,
  version wt_version
);

create trigger update_time_column before update on db_test_user
  for each row execute procedure update_time_column();

-- define the immutable fields for db_test_user
create trigger immutable_columns before update on db_test_user
  for each row execute procedure immutable_columns('create_time');

create trigger default_create_time_column before insert on db_test_user
  for each row execute procedure default_create_time();

create trigger update_version_column after update on db_test_user
  for each row execute procedure update_version_column();
  
create table if not exists db_test_car (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  model text,
  mpg smallint
);

create trigger update_time_column before update on db_test_car
  for each row execute procedure update_time_column();

-- define the immutable fields for db_test_car
create trigger immutable_columns before update on db_test_car
  for each row execute procedure immutable_columns('create_time');

create trigger default_create_time_column before insert on db_test_car
  for each row execute procedure default_create_time();

create table if not exists db_test_rental (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  user_id bigint not null
    references db_test_user(id),
  car_id bigint not null
    references db_test_car(id)
);

create trigger update_time_column before update on db_test_rental
  for each row execute procedure update_time_column();

-- define the immutable fields for db_test_rental
create trigger immutable_columns before update on db_test_rental
  for each row execute procedure immutable_columns('create_time');

create trigger default_create_time_column before insert on db_test_rental
  for each row execute procedure default_create_time();

create table if not exists db_test_scooter (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  private_id text not null unique,
  name text unique,
  model text,
  mpg smallint
);

create trigger update_time_column before update on db_test_scooter
  for each row execute procedure update_time_column();

-- define the immutable fields for db_test_scooter
create trigger immutable_columns before update on db_test_scooter
  for each row execute procedure immutable_columns('create_time');

create trigger default_create_time_column before insert on db_test_scooter
  for each row execute procedure default_create_time();

commit;
