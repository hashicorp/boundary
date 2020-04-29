CREATE TABLE if not exists db_test_user (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text NOT NULL UNIQUE,
  friendly_name text UNIQUE,
  name text,
  phone_number text,
  email text
);
CREATE TABLE if not exists db_test_car (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text NOT NULL UNIQUE,
  friendly_name text UNIQUE,
  model text,
  mpg smallint
);
CREATE TABLE if not exists db_test_rental (
  id bigint generated always as identity primary key,
  create_time timestamp with time zone default current_timestamp,
  update_time timestamp with time zone default current_timestamp,
  public_id text NOT NULL UNIQUE,
  friendly_name text UNIQUE,
  user_id bigint not null REFERENCES db_test_user(id),
  car_id bigint not null REFERENCES db_test_car(id)
);