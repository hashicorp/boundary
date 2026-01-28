-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- wh_user_id is similar to wt_user_id but for the data warehouse.
  -- Unlike wt_user_id, this allows for nulls.
  create domain wh_user_id as text
    check(
      length(trim(value)) > 10 or value in ('u_anon', 'u_auth', 'u_recovery')
    );
  comment on domain wh_user_id is
    '"u_anon", "u_auth", "u_recovery" or random ID generated with github.com/hashicorp/go-secure-stdlib/base62';

  create table wh_auth_token_accumulating_fact (
    auth_token_id wt_public_id primary key,
    user_id wh_user_id not null,
    user_key wh_dim_key not null
      references wh_user_dimension (key)
      on delete restrict
      on update cascade,

    -- date and time foreign keys
    auth_token_issued_date_key integer not null
      references wh_date_dimension (key)
      on delete restrict
      on update cascade,
    auth_token_issued_time_key integer not null
      references wh_time_of_day_dimension (key)
      on delete restrict
      on update cascade,
    auth_token_issued_time wh_timestamp,

    auth_token_deleted_date_key integer default -1 not null
      references wh_date_dimension (key)
      on delete restrict
      on update cascade,
    auth_token_deleted_time_key integer default -1 not null
      references wh_time_of_day_dimension (key)
      on delete restrict
      on update cascade,
    auth_token_deleted_time wh_timestamp default 'infinity'::timestamptz,

    auth_token_approximate_last_access_date_key integer default -1 not null
      references wh_date_dimension (key)
      on delete restrict
      on update cascade,
    auth_token_approximate_last_access_time_key integer default -1 not null
      references wh_time_of_day_dimension (key)
      on delete restrict
      on update cascade,
    auth_token_approximate_last_access_time wh_timestamp,

    auth_token_approximate_active_time_range tstzrange not null default tstzrange(current_timestamp, current_timestamp, '[]'),
    auth_token_valid_time_range              tstzrange not null default tstzrange(current_timestamp, 'infinity'::timestamptz, '[]'),

    -- the auth_token_count must always be 1
    -- this is a common pattern in data warehouse models
    -- See The Data Warehouse Toolkit, Third Edition
    -- by Ralph Kimball and Margy Ross for more information
    auth_token_count smallint default 1 not null
      constraint auth_token_count_must_be_1
      check(auth_token_count = 1),

    constraint last_accessed_time_lte_deleted_time
      check(auth_token_approximate_last_access_time <= auth_token_deleted_time),

    constraint active_time_lower_eq_issued_time
      check(lower(auth_token_approximate_active_time_range) = auth_token_issued_time),
    constraint active_time_upper_eq_last_accessed_time
      check(upper(auth_token_approximate_active_time_range) = auth_token_approximate_last_access_time),
    constraint valid_time_lower_eq_issued
      check(lower(auth_token_valid_time_range) = auth_token_issued_time),
    constraint valid_time_upper_eq_deleted
      check(upper(auth_token_valid_time_range) = auth_token_deleted_time),
    constraint active_time_contained_by_valid_time
      check(auth_token_approximate_active_time_range <@ auth_token_valid_time_range)
  );
  comment on table wh_auth_token_accumulating_fact is
    'The Wh Auth Token Accumulating Fact table is an accumulating fact table. '
    'The grain of the fact table is one row per auth token.';

  create function wh_insert_auth_token() returns trigger
  as $$
  begin
    select user_id
      into new.user_id
      from wh_user_dimension
     where key = new.user_key;

    return new;
  end;
  $$ language plpgsql;

  create trigger wh_insert_auth_token before insert on wh_auth_token_accumulating_fact
    for each row execute function wh_insert_auth_token();

  create trigger immutable_columns before update on wh_auth_token_accumulating_fact
    for each row execute procedure immutable_columns('user_id', 'user_key', 'auth_token_issued_time', 'auth_token_issued_time_key', 'auth_token_issued_date_key');

commit;
