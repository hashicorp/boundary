begin;

-- create test tables used in the unit tests for the internal/db package
-- these tables (db_test_user, db_test_car, db_test_rental) are not part
-- of the watchtower domain model... they are simply used for testing the internal/db package
create table if not exists db_test_user (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  phone_number text,
  email text,
  version text default rand_version_string(20)
);

create trigger 
  update_time_column 
before 
update on db_test_user 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on db_test_user 
  for each row execute procedure immutable_create_time_func();

create trigger 
  default_create_time_column
before
insert on db_test_user 
  for each row execute procedure default_create_time();

create trigger 
  update_version_column
after update on db_test_user
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

create trigger 
  update_time_column 
before 
update on db_test_car 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on db_test_car 
  for each row execute procedure immutable_create_time_func();

create trigger 
  default_create_time_column
before
insert on db_test_car
  for each row execute procedure default_create_time();

create table if not exists db_test_rental (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  user_id bigint not null references db_test_user(id),
  car_id bigint not null references db_test_car(id)
);

create trigger 
  update_time_column 
before 
update on db_test_rental 
  for each row execute procedure update_time_column();

create trigger 
  create_time_column
before
update on db_test_rental 
  for each row execute procedure immutable_create_time_func();

create trigger 
  default_create_time_column
before
insert on db_test_rental
  for each row execute procedure default_create_time();


commit;
