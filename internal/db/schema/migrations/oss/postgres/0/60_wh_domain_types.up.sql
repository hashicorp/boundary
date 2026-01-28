-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create extension if not exists "pgcrypto";

  create domain wh_inet_port as integer
  check(
    value > 0
    and
    value <= 65535
  );
  comment on domain wh_inet_port is
    'An ordinal number between 1 and 65535 representing a network port';

  create domain wh_bytes_transmitted as bigint
  check(
    value >= 0
  );
  comment on domain wh_bytes_transmitted is
    'A non-negative integer representing the number of bytes transmitted';

  -- wh_dim_id generates and returns a random ID which should be considered as
  -- universally unique.
  create or replace function wh_dim_id() returns text
  as $$
    select encode(digest(gen_random_bytes(16), 'sha256'), 'base64');
  $$ language sql;

  create domain wh_dim_id as text
  check(
    length(trim(value)) > 0
  );
  comment on domain wh_dim_id is
    'Random ID generated with pgcrypto';

  create domain wh_public_id as text
  check(
    value = 'None'
    or
    length(trim(value)) > 10
  );
  comment on domain wh_public_id is
    'Equivalent to wt_public_id but also allows the value to be ''None''';

  create domain wh_timestamp as timestamp with time zone not null;
  comment on domain wh_timestamp is
    'Timestamp used in warehouse tables';

  create domain wh_dim_text as text not null
  check(
    length(trim(value)) > 0
  );
  comment on domain wh_dim_text is
    'Text fields in dimension tables are always not null and always not empty strings';

  -- wh_date_id returns the wh_date_dimension id for ts.
  create or replace function wh_date_id(ts wh_timestamp) returns integer
  as $$
    select to_char(ts, 'YYYYMMDD')::integer;
  $$ language sql;

  -- wh_time_id returns the wh_time_of_day_dimension id for ts.
  create or replace function wh_time_id(ts wh_timestamp) returns integer
  as $$
    select to_char(ts, 'SSSS')::integer;
  $$ language sql;

  -- wh_date_id returns the wh_date_dimension id for current_timestamp.
  create or replace function wh_current_date_id() returns integer
  as $$
    select wh_date_id(current_timestamp);
  $$ language sql;

  -- wh_time_id returns the wh_time_of_day_dimension id for current_timestamp.
  create or replace function wh_current_time_id() returns integer
  as $$
    select wh_time_id(current_timestamp);
  $$ language sql;

commit;
