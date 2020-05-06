-- create test tables used in the unit tests for the internal/db package
-- these tables (db_test_user, db_test_car, db_test_rental) are not part
-- of the Watchtower domain model... they are simply used for testing the internal/db package
CREATE TABLE if not exists db_test_user (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text NOT NULL UNIQUE,
  name text UNIQUE,
  phone_number text,
  email text
);
CREATE TABLE if not exists db_test_car (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text NOT NULL UNIQUE,
  name text UNIQUE,
  model text,
  mpg smallint
);
CREATE TABLE if not exists db_test_rental (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text NOT NULL UNIQUE,
  name text UNIQUE,
  user_id bigint not null REFERENCES db_test_user(id),
  car_id bigint not null REFERENCES db_test_car(id)
);