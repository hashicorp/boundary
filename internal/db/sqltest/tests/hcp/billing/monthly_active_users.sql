-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(39);

  select lives_ok('truncate wh_auth_token_accumulating_fact,
                            wh_user_dimension,
                            wh_session_accumulating_fact,
                            wh_session_connection_accumulating_fact;',
                  'Truncate tables in preparation for testing');

  -- validate the warehouse fact tables are empty
  select is(count(*), 0::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 0::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;

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

  -- validate view returns 0 active users for last two months
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()), date_trunc('hour', now()), 0::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 0::bigint)
            $$);


  -- Now insert some edge cases to make sure we count them correctly

  -- active_time_range spans start of a month
  with month_range (previous) as (
    select tstzrange(date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), '[)')
  ),
  range (active, valid) as (
    select tstzrange(lower(previous) - interval '5 minutes', lower(previous) + interval '5 minutes', '[]'),
           tstzrange(lower(previous) - interval '5 minutes', 'infinity'::timestamptz)
      from month_range
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                user_key,
              auth_token_issued_date_key,                   auth_token_issued_time_key,                    auth_token_issued_time,
              auth_token_deleted_date_key,                  auth_token_deleted_time_key,                   auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,  auth_token_approximate_last_access_time_key,   auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select 'at____atok1',                                 user_key.key,
             wh_date_key(lower(range.valid)),               wh_time_key(lower(range.valid)),               lower(range.valid),
             coalesce(wh_date_key(upper(range.valid)), -1), coalesce(wh_time_key(upper(range.valid)), -1), upper(range.valid),
             wh_date_key(upper(range.active)),              wh_time_key(upper(range.active)),              upper(range.active),
             range.active,
             range.valid,
             1
        from range, user_key;

  select is(count(*), 1::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  0::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- active_time_range within start/end of month
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with month_range (previous) as (
    select tstzrange(date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), '[)')
  ),
  range (active, valid) as (
    select tstzrange(lower(previous) + interval '5 minutes', lower(previous) + interval '10 minutes', '[]'),
           tstzrange(lower(previous) + interval '5 minutes', 'infinity'::timestamptz)
      from month_range
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                user_key,
              auth_token_issued_date_key,                   auth_token_issued_time_key,                    auth_token_issued_time,
              auth_token_deleted_date_key,                  auth_token_deleted_time_key,                   auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,  auth_token_approximate_last_access_time_key,   auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select 'at____atok1',                                 user_key.key,
             wh_date_key(lower(range.valid)),               wh_time_key(lower(range.valid)),               lower(range.valid),
             coalesce(wh_date_key(upper(range.valid)), -1), coalesce(wh_time_key(upper(range.valid)), -1), upper(range.valid),
             wh_date_key(upper(range.active)),              wh_time_key(upper(range.active)),              upper(range.active),
             range.active,
             range.valid,
             1
        from range, user_key;

  select is(count(*), 1::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  0::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- active_time_range spances end of month
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with month_range (previous) as (
    select tstzrange(date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), '[)')
  ),
  range (active, valid) as (
    select tstzrange(upper(previous) - interval '5 minutes', upper(previous) + interval '5 minutes', '[]'),
           tstzrange(upper(previous) - interval '5 minutes', 'infinity'::timestamptz)
      from month_range
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                user_key,
              auth_token_issued_date_key,                   auth_token_issued_time_key,                    auth_token_issued_time,
              auth_token_deleted_date_key,                  auth_token_deleted_time_key,                   auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,  auth_token_approximate_last_access_time_key,   auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select 'at____atok1',                                 user_key.key,
             wh_date_key(lower(range.valid)),               wh_time_key(lower(range.valid)),               lower(range.valid),
             coalesce(wh_date_key(upper(range.valid)), -1), coalesce(wh_time_key(upper(range.valid)), -1), upper(range.valid),
             wh_date_key(upper(range.active)),              wh_time_key(upper(range.active)),              upper(range.active),
             range.active,
             range.valid,
             1
        from range, user_key;

  select is(count(*), 1::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  1::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- active_time_range starts on start of month
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with month_range (previous) as (
    select tstzrange(date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), '[)')
  ),
  range (active, valid) as (
    select tstzrange(lower(previous), lower(previous) + interval '5 minutes', '[]'),
           tstzrange(lower(previous), 'infinity'::timestamptz)
      from month_range
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                user_key,
              auth_token_issued_date_key,                   auth_token_issued_time_key,                    auth_token_issued_time,
              auth_token_deleted_date_key,                  auth_token_deleted_time_key,                   auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,  auth_token_approximate_last_access_time_key,   auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select 'at____atok1',                                 user_key.key,
             wh_date_key(lower(range.valid)),               wh_time_key(lower(range.valid)),               lower(range.valid),
             coalesce(wh_date_key(upper(range.valid)), -1), coalesce(wh_time_key(upper(range.valid)), -1), upper(range.valid),
             wh_date_key(upper(range.active)),              wh_time_key(upper(range.active)),              upper(range.active),
             range.active,
             range.valid,
             1
        from range, user_key;

  select is(count(*), 1::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  0::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- active_time_range ends on end of month
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with month_range (previous) as (
    select tstzrange(date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), '[)')
  ),
  range (active, valid) as (
    -- the resolution on a timestamptz is 1 microsecond, so subtracting one microsecond from the upper bound of
    -- the month range puts us as close to the "end of month" as possible, wthout going over.
    -- https://www.postgresql.org/docs/current/datatype-datetime.html#DATATYPE-DATETIME
    select tstzrange(lower(previous) + interval '5 minutes', upper(previous) - interval '1 microsecond', '[]'),
           tstzrange(lower(previous) + interval '5 minutes', 'infinity'::timestamptz)
      from month_range
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                user_key,
              auth_token_issued_date_key,                   auth_token_issued_time_key,                    auth_token_issued_time,
              auth_token_deleted_date_key,                  auth_token_deleted_time_key,                   auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,  auth_token_approximate_last_access_time_key,   auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select 'at____atok1',                                 user_key.key,
             wh_date_key(lower(range.valid)),               wh_time_key(lower(range.valid)),               lower(range.valid),
             coalesce(wh_date_key(upper(range.valid)), -1), coalesce(wh_time_key(upper(range.valid)), -1), upper(range.valid),
             wh_date_key(upper(range.active)),              wh_time_key(upper(range.active)),              upper(range.active),
             range.active,
             range.valid,
             1
        from range, user_key;

  select is(count(*), 1::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  0::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- active_time_range starts on end of month
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with month_range (previous) as (
    select tstzrange(date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), '[)')
  ),
  range (active, valid) as (
    -- the resolution on a timestamptz is 1 microsecond, so subtracting one microsecond from the upper bound of
    -- the month range puts us as close to the "end of month" as possible, wthout going over.
    -- https://www.postgresql.org/docs/current/datatype-datetime.html#DATATYPE-DATETIME
    select tstzrange(upper(previous) - interval '1 microsecond', upper(previous) + '5 minutes', '[]'),
           tstzrange(upper(previous) - interval '1 microsecond', 'infinity'::timestamptz)
      from month_range
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                user_key,
              auth_token_issued_date_key,                   auth_token_issued_time_key,                    auth_token_issued_time,
              auth_token_deleted_date_key,                  auth_token_deleted_time_key,                   auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,  auth_token_approximate_last_access_time_key,   auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select 'at____atok1',                                 user_key.key,
             wh_date_key(lower(range.valid)),               wh_time_key(lower(range.valid)),               lower(range.valid),
             coalesce(wh_date_key(upper(range.valid)), -1), coalesce(wh_time_key(upper(range.valid)), -1), upper(range.valid),
             wh_date_key(upper(range.active)),              wh_time_key(upper(range.active)),              upper(range.active),
             range.active,
             range.valid,
             1
        from range, user_key;

  select is(count(*), 1::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  1::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- active_time_range ends on start of month
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with month_range (previous) as (
    select tstzrange(date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), '[)')
  ),
  range (active, valid) as (
    select tstzrange(upper(previous) - interval '5 minutes', upper(previous), '[]'),
           tstzrange(upper(previous) - interval '5 minutes', 'infinity'::timestamptz)
      from month_range
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                user_key,
              auth_token_issued_date_key,                   auth_token_issued_time_key,                    auth_token_issued_time,
              auth_token_deleted_date_key,                  auth_token_deleted_time_key,                   auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,  auth_token_approximate_last_access_time_key,   auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select 'at____atok1',                                 user_key.key,
             wh_date_key(lower(range.valid)),               wh_time_key(lower(range.valid)),               lower(range.valid),
             coalesce(wh_date_key(upper(range.valid)), -1), coalesce(wh_time_key(upper(range.valid)), -1), upper(range.valid),
             wh_date_key(upper(range.active)),              wh_time_key(upper(range.active)),              upper(range.active),
             range.active,
             range.valid,
             1
        from range, user_key;

  select is(count(*), 1::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  1::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- multiple tokens for a user within month count as single user
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with token (public_id, active) as (
    select *
      from (values
           ('at____atok1', tstzrange(date_trunc('month', now() - interval '1 month'),
                                     date_trunc('month', now() - interval '1 month') + interval '5 minutes')),
           ('at____atok2', tstzrange(date_trunc('month', now() - interval '1 month') + interval '10 minutes',
                                     date_trunc('month', now() - interval '1 month') + interval '15 minutes'))
           ) as t (public_id, active)
  ),
  user_key (key) as (
    select key
      from wh_user_dimension
     where user_id = 'u_____user1'
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                 user_key,
              auth_token_issued_date_key,                    auth_token_issued_time_key,                     auth_token_issued_time,
              auth_token_deleted_date_key,                   auth_token_deleted_time_key,                    auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,   auth_token_approximate_last_access_time_key,    auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select token.public_id,                                user_key.key,
             wh_date_key(lower(token.active)),               wh_time_key(lower(token.active)),               lower(token.active),
             coalesce(wh_date_key(upper(token.active)), -1), coalesce(wh_time_key(upper(token.active)), -1), upper(token.active),
             wh_date_key(upper(token.active)),               wh_time_key(upper(token.active)),               upper(token.active),
             token.active,
             token.active,
             1
        from token, user_key;

  select is(count(*), 2::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 1::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  0::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 1::bigint)
            $$);

  -- multiple tokens for multiple users should get counted correctly
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
    'u_____user2',           'None',                   'None',
    'a______acc2',           'None',                   'None',                        'None',
    'am______am1',           'None',                   'None',                        'None',
    'o______org1',           'None',                   'None',
    'current',
    now(),                   'infinity'::timestamptz,
    'None',                  'None',                   'None',                        'None'
  ),(
    'u_____user3',           'None',                   'None',
    'a______acc3',           'None',                   'None',                        'None',
    'am______am1',           'None',                   'None',                        'None',
    'o______org1',           'None',                   'None',
    'current',
    now(),                   'infinity'::timestamptz,
    'None',                  'None',                   'None',                        'None'
  );
  select lives_ok('truncate wh_auth_token_accumulating_fact');
  with token (user_id, public_id, active) as (
    select *
      from (values
           ('u_____user1', 'at___u1tok1', tstzrange(date_trunc('month', now() - interval '1 month'),
                                                    date_trunc('month', now() - interval '1 month') + interval '5 minutes')),
           ('u_____user1', 'at___u1tok2', tstzrange(date_trunc('month', now() - interval '1 month') + interval '10 minutes',
                                                    date_trunc('month', now() - interval '1 month') + interval '15 minutes')),
           ('u_____user2', 'at___u2tok1', tstzrange(date_trunc('month', now() - interval '1 month'),
                                                    date_trunc('month', now() - interval '1 month') + interval '5 minutes')),
           ('u_____user2', 'at___u2tok2', tstzrange(date_trunc('month', now() - interval '1 month') + interval '10 minutes',
                                                    date_trunc('month', now() - interval '1 month') + interval '15 minutes')),
           ('u_____user3', 'at___u3tok1', tstzrange(date_trunc('month', now() - interval '1 month'),
                                                    date_trunc('month', now() - interval '1 month') + interval '5 minutes')),
           ('u_____user3', 'at___u3tok2', tstzrange(date_trunc('month', now() - interval '1 month') + interval '10 minutes',
                                                    date_trunc('month', now() - interval '1 month') + interval '15 minutes')),
           ('u_____user3', 'at___u3tok3', tstzrange(date_trunc('month', now() - interval '1 month') + interval '10 minutes',
                                                    date_trunc('month', now() - interval '1 month') + interval '15 minutes'))
           ) as t (user_id, public_id, active)
  ),
  token_key (user_key, public_id, active) as (
    select whud.key, token.public_id, token.active
      from wh_user_dimension as whud
      join token
        on whud.user_id = token.user_id
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                 user_key,
              auth_token_issued_date_key,                    auth_token_issued_time_key,                     auth_token_issued_time,
              auth_token_deleted_date_key,                   auth_token_deleted_time_key,                    auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,   auth_token_approximate_last_access_time_key,    auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select token_key.public_id,                                token_key.user_key,
             wh_date_key(lower(token_key.active)),               wh_time_key(lower(token_key.active)),               lower(token_key.active),
             coalesce(wh_date_key(upper(token_key.active)), -1), coalesce(wh_time_key(upper(token_key.active)), -1), upper(token_key.active),
             wh_date_key(upper(token_key.active)),               wh_time_key(upper(token_key.active)),               upper(token_key.active),
             token_key.active,
             token_key.active,
             1
        from token_key;

  select is(count(*), 7::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 3::bigint, 'wh_user_dimension is not empty')               from wh_user_dimension;
  select results_eq(
            'select * from hcp_billing_monthly_active_users_last_2_months',
            $$
            values (date_trunc('month', now()),                      date_trunc('hour', now()),  0::bigint),
                   (date_trunc('month', now() - interval '1 month'), date_trunc('month', now()), 3::bigint)
            $$);

  select * from finish();
rollback;
