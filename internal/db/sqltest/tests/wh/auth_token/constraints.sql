-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(13);

  -- Create a user dimension for corresponding auth token's user.
  insert into wh_user_dimension (
    user_id,                 user_name,                user_description,
    auth_account_id,         auth_account_type,        auth_account_name,             auth_account_description,
    auth_method_id,          auth_method_type,         auth_method_name,              auth_method_description,
    user_organization_id,    user_organization_name,   user_organization_description,
    current_row_indicator,
    row_effective_time,      row_expiration_time,
    auth_method_external_id, auth_account_external_id, auth_account_full_name,        auth_account_email
  ) values (
    'u_____user1',           'None',                   'None',
    'a______acc1',           'None',                   'None',                        'None',
    'am______am1',           'None',                   'None',                        'None',
    'o______org1',           'None',                   'None',
    'current',
    now(),                   'infinity'::timestamptz,
    'None',                  'None',                   'None',                        'None'
  );


  prepare insert_access_time_after_delete as
    with
    issued_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 10:00:00'::timestamptz),
             wh_time_key('2023-12-13 10:00:00'::timestamptz),
                         '2023-12-13 10:00:00'::timestamptz
    ),
    accessed_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 12:00:00'::timestamptz),
             wh_time_key('2023-12-13 12:00:00'::timestamptz),
                         '2023-12-13 12:00:00'::timestamptz
    ),
    deleted_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 11:00:00'::timestamptz),
             wh_time_key('2023-12-13 11:00:00'::timestamptz),
                         '2023-12-13 11:00:00'::timestamptz
    ),
    user_dim(key) as (
      select key
        from wh_user_dimension
       where user_id = 'u_____user1'
    )
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_deleted_date_key,
                auth_token_deleted_time_key,
                auth_token_deleted_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range,
                auth_token_count
    )
         select 'tok___token1',
                user_dim.key,
                issued_timestamp.date_dim_key,
                issued_timestamp.time_dim_key,
                issued_timestamp.ts,
                deleted_timestamp.date_dim_key,
                deleted_timestamp.time_dim_key,
                deleted_timestamp.ts,
                accessed_timestamp.date_dim_key,
                accessed_timestamp.time_dim_key,
                accessed_timestamp.ts,
                tstzrange(issued_timestamp.ts, accessed_timestamp.ts),
                tstzrange(issued_timestamp.ts, accessed_timestamp.ts),
                1
           from user_dim,
                issued_timestamp,
                deleted_timestamp,
                accessed_timestamp;
  select throws_ok(
    'insert_access_time_after_delete',
    '23514',
    'new row for relation "wh_auth_token_accumulating_fact" violates check constraint "last_accessed_time_lte_deleted_time"'
  );

  prepare insert_active_time_after_issued as
    with
    issued_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 10:00:00'::timestamptz),
             wh_time_key('2023-12-13 10:00:00'::timestamptz),
                         '2023-12-13 10:00:00'::timestamptz
    ),
    accessed_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 12:00:00'::timestamptz),
             wh_time_key('2023-12-13 12:00:00'::timestamptz),
                         '2023-12-13 12:00:00'::timestamptz
    ),
    deleted_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 13:00:00'::timestamptz),
             wh_time_key('2023-12-13 13:00:00'::timestamptz),
                         '2023-12-13 13:00:00'::timestamptz
    ),
    user_dim(key) as (
      select key
        from wh_user_dimension
       where user_id = 'u_____user1'
    )
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_deleted_date_key,
                auth_token_deleted_time_key,
                auth_token_deleted_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range,
                auth_token_count
    )
         select 'tok___token2',
                user_dim.key,
                issued_timestamp.date_dim_key,
                issued_timestamp.time_dim_key,
                issued_timestamp.ts,
                deleted_timestamp.date_dim_key,
                deleted_timestamp.time_dim_key,
                deleted_timestamp.ts,
                accessed_timestamp.date_dim_key,
                accessed_timestamp.time_dim_key,
                accessed_timestamp.ts,
                tstzrange(issued_timestamp.ts + interval '10 minutes', accessed_timestamp.ts),
                tstzrange(issued_timestamp.ts, deleted_timestamp.ts),
                1
           from user_dim,
                issued_timestamp,
                deleted_timestamp,
                accessed_timestamp;
  select throws_ok(
    'insert_active_time_after_issued',
    '23514',
    'new row for relation "wh_auth_token_accumulating_fact" violates check constraint "active_time_lower_eq_issued_time"'
  );

  prepare insert_active_time_before_access as
    with
    issued_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 10:00:00'::timestamptz),
             wh_time_key('2023-12-13 10:00:00'::timestamptz),
                         '2023-12-13 10:00:00'::timestamptz
    ),
    accessed_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 12:00:00'::timestamptz),
             wh_time_key('2023-12-13 12:00:00'::timestamptz),
                         '2023-12-13 12:00:00'::timestamptz
    ),
    deleted_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 13:00:00'::timestamptz),
             wh_time_key('2023-12-13 13:00:00'::timestamptz),
                         '2023-12-13 13:00:00'::timestamptz
    ),
    user_dim(key) as (
      select key
        from wh_user_dimension
       where user_id = 'u_____user1'
    )
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_deleted_date_key,
                auth_token_deleted_time_key,
                auth_token_deleted_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range,
                auth_token_count
    )
         select 'tok___token2',
                user_dim.key,
                issued_timestamp.date_dim_key,
                issued_timestamp.time_dim_key,
                issued_timestamp.ts,
                deleted_timestamp.date_dim_key,
                deleted_timestamp.time_dim_key,
                deleted_timestamp.ts,
                accessed_timestamp.date_dim_key,
                accessed_timestamp.time_dim_key,
                accessed_timestamp.ts,
                tstzrange(issued_timestamp.ts, accessed_timestamp.ts - interval '10 minutes'),
                tstzrange(issued_timestamp.ts, deleted_timestamp.ts),
                1
           from user_dim,
                issued_timestamp,
                deleted_timestamp,
                accessed_timestamp;
  select throws_ok(
    'insert_active_time_before_access',
    '23514',
    'new row for relation "wh_auth_token_accumulating_fact" violates check constraint "active_time_upper_eq_last_accessed_time"'
  );

  prepare insert_active_not_contained_by_valid as
    with
    issued_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 10:00:00'::timestamptz),
             wh_time_key('2023-12-13 10:00:00'::timestamptz),
                         '2023-12-13 10:00:00'::timestamptz
    ),
    accessed_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 12:00:00'::timestamptz),
             wh_time_key('2023-12-13 12:00:00'::timestamptz),
                         '2023-12-13 12:00:00'::timestamptz
    ),
    deleted_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 11:00:00'::timestamptz),
             wh_time_key('2023-12-13 11:00:00'::timestamptz),
                         '2023-12-13 11:00:00'::timestamptz
    ),
    user_dim(key) as (
      select key
        from wh_user_dimension
       where user_id = 'u_____user1'
    )
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_deleted_date_key,
                auth_token_deleted_time_key,
                auth_token_deleted_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range,
                auth_token_count
    )
         select 'tok___token1',
                user_dim.key,
                issued_timestamp.date_dim_key,
                issued_timestamp.time_dim_key,
                issued_timestamp.ts,
                deleted_timestamp.date_dim_key,
                deleted_timestamp.time_dim_key,
                deleted_timestamp.ts,
                accessed_timestamp.date_dim_key,
                accessed_timestamp.time_dim_key,
                accessed_timestamp.ts,
                tstzrange(issued_timestamp.ts, accessed_timestamp.ts),
                tstzrange(issued_timestamp.ts, deleted_timestamp.ts),
                1
           from user_dim,
                issued_timestamp,
                deleted_timestamp,
                accessed_timestamp;
  select throws_ok(
    'insert_active_not_contained_by_valid',
    '23514',
    'new row for relation "wh_auth_token_accumulating_fact" violates check constraint "active_time_contained_by_valid_time"'
  );

  prepare insert_valid_time_before_issued as
    with
    issued_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 10:00:00'::timestamptz),
             wh_time_key('2023-12-13 10:00:00'::timestamptz),
                         '2023-12-13 10:00:00'::timestamptz
    ),
    accessed_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 12:00:00'::timestamptz),
             wh_time_key('2023-12-13 12:00:00'::timestamptz),
                         '2023-12-13 12:00:00'::timestamptz
    ),
    deleted_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 13:00:00'::timestamptz),
             wh_time_key('2023-12-13 13:00:00'::timestamptz),
                         '2023-12-13 13:00:00'::timestamptz
    ),
    user_dim(key) as (
      select key
        from wh_user_dimension
       where user_id = 'u_____user1'
    )
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_deleted_date_key,
                auth_token_deleted_time_key,
                auth_token_deleted_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range,
                auth_token_count
    )
         select 'tok___token2',
                user_dim.key,
                issued_timestamp.date_dim_key,
                issued_timestamp.time_dim_key,
                issued_timestamp.ts,
                deleted_timestamp.date_dim_key,
                deleted_timestamp.time_dim_key,
                deleted_timestamp.ts,
                accessed_timestamp.date_dim_key,
                accessed_timestamp.time_dim_key,
                accessed_timestamp.ts,
                tstzrange(issued_timestamp.ts, accessed_timestamp.ts),
                tstzrange(issued_timestamp.ts - interval '10 minutes', deleted_timestamp.ts),
                1
           from user_dim,
                issued_timestamp,
                deleted_timestamp,
                accessed_timestamp;
  select throws_ok(
    'insert_valid_time_before_issued',
    '23514',
    'new row for relation "wh_auth_token_accumulating_fact" violates check constraint "valid_time_lower_eq_issued"'
  );

  prepare insert_valid_time_before_deleted as
    with
    issued_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 10:00:00'::timestamptz),
             wh_time_key('2023-12-13 10:00:00'::timestamptz),
                         '2023-12-13 10:00:00'::timestamptz
    ),
    accessed_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 12:00:00'::timestamptz),
             wh_time_key('2023-12-13 12:00:00'::timestamptz),
                         '2023-12-13 12:00:00'::timestamptz
    ),
    deleted_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 13:00:00'::timestamptz),
             wh_time_key('2023-12-13 13:00:00'::timestamptz),
                         '2023-12-13 13:00:00'::timestamptz
    ),
    user_dim(key) as (
      select key
        from wh_user_dimension
       where user_id = 'u_____user1'
    )
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_deleted_date_key,
                auth_token_deleted_time_key,
                auth_token_deleted_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range,
                auth_token_count
    )
         select 'tok___token2',
                user_dim.key,
                issued_timestamp.date_dim_key,
                issued_timestamp.time_dim_key,
                issued_timestamp.ts,
                deleted_timestamp.date_dim_key,
                deleted_timestamp.time_dim_key,
                deleted_timestamp.ts,
                accessed_timestamp.date_dim_key,
                accessed_timestamp.time_dim_key,
                accessed_timestamp.ts,
                tstzrange(issued_timestamp.ts, accessed_timestamp.ts),
                tstzrange(issued_timestamp.ts, deleted_timestamp.ts - interval '10 minutes'),
                1
           from user_dim,
                issued_timestamp,
                deleted_timestamp,
                accessed_timestamp;
  select throws_ok(
    'insert_valid_time_before_deleted',
    '23514',
    'new row for relation "wh_auth_token_accumulating_fact" violates check constraint "valid_time_upper_eq_deleted"'
  );

  prepare insert_success as
    with
    issued_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 10:00:00'::timestamptz),
             wh_time_key('2023-12-13 10:00:00'::timestamptz),
                         '2023-12-13 10:00:00'::timestamptz
    ),
    accessed_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 12:00:00'::timestamptz),
             wh_time_key('2023-12-13 12:00:00'::timestamptz),
                         '2023-12-13 12:00:00'::timestamptz
    ),
    deleted_timestamp(date_dim_key, time_dim_key, ts) as (
      select wh_date_key('2023-12-13 13:00:00'::timestamptz),
             wh_time_key('2023-12-13 13:00:00'::timestamptz),
                         '2023-12-13 13:00:00'::timestamptz
    ),
    user_dim(key) as (
      select key
        from wh_user_dimension
       where user_id = 'u_____user1'
    )
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_deleted_date_key,
                auth_token_deleted_time_key,
                auth_token_deleted_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range,
                auth_token_count
    )
         select 'tok___token2',
                user_dim.key,
                issued_timestamp.date_dim_key,
                issued_timestamp.time_dim_key,
                issued_timestamp.ts,
                deleted_timestamp.date_dim_key,
                deleted_timestamp.time_dim_key,
                deleted_timestamp.ts,
                accessed_timestamp.date_dim_key,
                accessed_timestamp.time_dim_key,
                accessed_timestamp.ts,
                tstzrange(issued_timestamp.ts, accessed_timestamp.ts),
                tstzrange(issued_timestamp.ts, deleted_timestamp.ts),
                1
           from user_dim,
                issued_timestamp,
                deleted_timestamp,
                accessed_timestamp;
  select lives_ok('insert_success');
  -- ensure user_id was properly set
  select is(wh_auth_token_accumulating_fact.user_id, 'u_____user1')
    from wh_auth_token_accumulating_fact
   where auth_token_id = 'tok___token2';

  prepare update_user_id as
    update wh_auth_token_accumulating_fact set user_id = 'u_____user2'
     where auth_token_id = 'tok___token2';
  select throws_ok(
    'update_user_id',
    '23601',
    'immutable column: wh_auth_token_accumulating_fact.user_id'
  );

  prepare update_user_key as
    update wh_auth_token_accumulating_fact set user_key = 'key_2'
     where auth_token_id = 'tok___token2';
  select throws_ok(
    'update_user_key',
    '23601',
    'immutable column: wh_auth_token_accumulating_fact.user_key'
  );

  prepare update_auth_token_issued_time as
    update wh_auth_token_accumulating_fact set auth_token_issued_time = '2023-12-13 11:01:00'::timestamptz
     where auth_token_id = 'tok___token2';
  select throws_ok(
    'update_auth_token_issued_time',
    '23601',
    'immutable column: wh_auth_token_accumulating_fact.auth_token_issued_time'
  );

  prepare update_auth_token_issued_time_key as
    update wh_auth_token_accumulating_fact set auth_token_issued_time_key = wh_time_key('2023-12-13 11:01:00'::timestamptz)
     where auth_token_id = 'tok___token2';
  select throws_ok(
    'update_auth_token_issued_time_key',
    '23601',
    'immutable column: wh_auth_token_accumulating_fact.auth_token_issued_time_key'
  );

  prepare update_auth_token_issued_date_key as
    update wh_auth_token_accumulating_fact set auth_token_issued_date_key = wh_date_key('2023-12-14 11:00:00'::timestamptz)
     where auth_token_id = 'tok___token2';
  select throws_ok(
    'update_auth_token_issued_date_key',
    '23601',
    'immutable column: wh_auth_token_accumulating_fact.auth_token_issued_date_key'
  );

  select * from finish();
rollback;
