-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(11);

  create function test_is_not_same_month(start_time timestamptz, end_time timestamptz) returns boolean
  as $$
  begin
    if date_trunc('month', start_time) != date_trunc('month', end_time) then
      return true;
    end if;
    return false;
  end;
  $$ language plpgsql;

  select lives_ok('truncate wh_auth_token_accumulating_fact,
                            wh_user_dimension,
                            wh_session_accumulating_fact,
                            wh_session_connection_accumulating_fact;',
                  'Truncate tables in preparation for testing');

  -- generate auth tokens for users simulating the server being configured to use a different time zone.
  set time zone 'NZ';
  with
  month_range (date_key, time_key, month) as (
    select wh_date_key(s), wh_time_key(s), s
      from generate_series(date_trunc('month', now()) - interval '1 year',
                           date_trunc('month', now()) - interval '1 month',
                           interval '1 month') as s
  ),
  users (user_id, u) as (
    select 'u_____user'||u, u
      from generate_series(1, 6, 1) as u
  ),
  user_key (key, user_id) as (
    insert into wh_user_dimension (
                user_id,                 user_name,                user_description,
                auth_account_id,         auth_account_type,        auth_account_name,             auth_account_description,
                auth_method_id,          auth_method_type,         auth_method_name,              auth_method_description,
                user_organization_id,    user_organization_name,   user_organization_description,
                current_row_indicator,
                row_effective_time,      row_expiration_time,
                auth_method_external_id, auth_account_external_id, auth_account_full_name,        auth_account_email)
         select users.user_id,           'None',                   'None',
                'a______acc1',           'None',                   'None',                        'None',
                'am______am1',           'None',                   'None',                        'None',
                'o______org1',           'None',                   'None',
                'current',
                now(),                   'infinity'::timestamptz,
                'None',                  'None',                   'None',                        'None'
           from users
      returning key, user_id
  ),
  tokens (date_key, time_key, user_id, token_id) as (
    select wh_date_key(s), wh_time_key(s), users.user_id, 't_____u'||users.u||'tok'||s as token_id
      from users,
           generate_series(date_trunc('month', now()) - interval '1 year',
                           date_trunc('month', now()) - interval '1 month',
                           interval '1 month') as s
  ),
  tokens_user_keys (date_key, time_key, user_id, token_id, user_key) as (
    select tokens.date_key, tokens.time_key, tokens.user_id, tokens.token_id, user_key.key
      from tokens
      join user_key
        on user_key.user_id = tokens.user_id
  ),
  auth_tokens (user_key, user_id, token_id, valid_range) as (
    select tokens_user_keys.user_key, tokens_user_keys.user_id, tokens_user_keys.token_id, tstzrange(month_range.month, month_range.month + interval '5 minutes', '[)')
      from tokens_user_keys
      join month_range
        on month_range.date_key = tokens_user_keys.date_key
       and month_range.time_key = tokens_user_keys.time_key
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                            user_key,
              auth_token_issued_date_key,                               auth_token_issued_time_key,                                auth_token_issued_time,
              auth_token_deleted_date_key,                              auth_token_deleted_time_key,                               auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,              auth_token_approximate_last_access_time_key,               auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select auth_tokens.token_id,                                      auth_tokens.user_key,
             wh_date_key(lower(auth_tokens.valid_range)),               wh_time_key(lower(auth_tokens.valid_range)),               lower(auth_tokens.valid_range),
             coalesce(wh_date_key(upper(auth_tokens.valid_range)), -1), coalesce(wh_time_key(upper(auth_tokens.valid_range)), -1), upper(auth_tokens.valid_range),
             wh_date_key(upper(auth_tokens.valid_range)),               wh_time_key(upper(auth_tokens.valid_range)),               upper(auth_tokens.valid_range),
             auth_tokens.valid_range,
             auth_tokens.valid_range,
             1
        from auth_tokens;
  select is(count(*), 72::bigint, 'wh_auth_token_accumulating_fact is not empty') from wh_auth_token_accumulating_fact;
  select is(count(*), 6::bigint,  'wh_user_dimension is not empty')               from wh_user_dimension;

  -- calling the view directly yields results at NZ month boundaries.
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else results_eq(
           'select * from hcp_billing_monthly_active_users_all',
           $$
           values (date_trunc('month', now(),                       'nz'), date_trunc('hour',  now(),                       'nz'), 0::bigint),
                  (date_trunc('month', now() - interval  '1 month', 'nz'), date_trunc('month', now(),                       'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '2 month', 'nz'), date_trunc('month', now() - interval  '1 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '3 month', 'nz'), date_trunc('month', now() - interval  '2 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '4 month', 'nz'), date_trunc('month', now() - interval  '3 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '5 month', 'nz'), date_trunc('month', now() - interval  '4 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '6 month', 'nz'), date_trunc('month', now() - interval  '5 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '7 month', 'nz'), date_trunc('month', now() - interval  '6 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '8 month', 'nz'), date_trunc('month', now() - interval  '7 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval  '9 month', 'nz'), date_trunc('month', now() - interval  '8 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval '10 month', 'nz'), date_trunc('month', now() - interval  '9 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval '11 month', 'nz'), date_trunc('month', now() - interval '10 month', 'nz'), 6::bigint),
                  (date_trunc('month', now() - interval '12 month', 'nz'), date_trunc('month', now() - interval '11 month', 'nz'), 6::bigint)
            $$)
         end;


  -- calling the function yields results at UTC month boundaries.
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else results_eq(
           'select count(*) from hcp_billing_monthly_active_users_all()',
           $$
           values (14::bigint);
           $$)
         end;
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else results_eq(
           'select * from hcp_billing_monthly_active_users_all()',
           $$
           values (date_trunc('month', now(),                       'utc'), date_trunc('hour',  now(),                       'utc'), 0::bigint),
                  (date_trunc('month', now() - interval  '1 month', 'utc'), date_trunc('month', now(),                       'utc'), 0::bigint),
                  (date_trunc('month', now() - interval  '2 month', 'utc'), date_trunc('month', now() - interval  '1 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '3 month', 'utc'), date_trunc('month', now() - interval  '2 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '4 month', 'utc'), date_trunc('month', now() - interval  '3 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '5 month', 'utc'), date_trunc('month', now() - interval  '4 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '6 month', 'utc'), date_trunc('month', now() - interval  '5 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '7 month', 'utc'), date_trunc('month', now() - interval  '6 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '8 month', 'utc'), date_trunc('month', now() - interval  '7 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '9 month', 'utc'), date_trunc('month', now() - interval  '8 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '10 month', 'utc'), date_trunc('month', now() - interval  '9 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '11 month', 'utc'), date_trunc('month', now() - interval '10 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '12 month', 'utc'), date_trunc('month', now() - interval '11 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '13 month', 'utc'), date_trunc('month', now() - interval '12 month', 'utc'), 6::bigint)
           $$)
         end;
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else results_ne(
            'select * from hcp_billing_monthly_active_users_all()',
            'select * from hcp_billing_monthly_active_users_all')
         end;
  -- can provide a start time (inclusive) to limit the results.
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else results_eq(
           $$
           select * from hcp_billing_monthly_active_users_all(date_trunc('month', now() - interval '5 month', 'utc'));
           $$,
           $$
           values (date_trunc('month', now(),                       'utc'), date_trunc('hour',  now(),                       'utc'), 0::bigint),
                  (date_trunc('month', now() - interval  '1 month', 'utc'), date_trunc('month', now(),                       'utc'), 0::bigint),
                  (date_trunc('month', now() - interval  '2 month', 'utc'), date_trunc('month', now() - interval  '1 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '3 month', 'utc'), date_trunc('month', now() - interval  '2 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '4 month', 'utc'), date_trunc('month', now() - interval  '3 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '5 month', 'utc'), date_trunc('month', now() - interval  '4 month', 'utc'), 6::bigint)
           $$)
         end;
  -- can provide a start time (inclusive) and end time (exclusive) to limit results.
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else results_eq(
           $$
           select * from hcp_billing_monthly_active_users_all(date_trunc('month', now() - interval '5 month', 'utc'),
                                                              date_trunc('month', now() - interval '3 month', 'utc'));
           $$,
           $$
           values (date_trunc('month', now() - interval  '4 month', 'utc'), date_trunc('month', now() - interval  '3 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '5 month', 'utc'), date_trunc('month', now() - interval  '4 month', 'utc'), 6::bigint)
           $$)
         end;
  -- can provide an end time (exclusive) to limit results.
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else results_eq(
           $$
           select * from hcp_billing_monthly_active_users_all(null,
                                                              date_trunc('month', now() - interval '3 month', 'utc'));
           $$,
           $$
           values (date_trunc('month', now() - interval  '4 month', 'utc'), date_trunc('month', now() - interval  '3 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '5 month', 'utc'), date_trunc('month', now() - interval  '4 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '6 month', 'utc'), date_trunc('month', now() - interval  '5 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '7 month', 'utc'), date_trunc('month', now() - interval  '6 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '8 month', 'utc'), date_trunc('month', now() - interval  '7 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval  '9 month', 'utc'), date_trunc('month', now() - interval  '8 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '10 month', 'utc'), date_trunc('month', now() - interval  '9 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '11 month', 'utc'), date_trunc('month', now() - interval '10 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '12 month', 'utc'), date_trunc('month', now() - interval '11 month', 'utc'), 6::bigint),
                  (date_trunc('month', now() - interval '13 month', 'utc'), date_trunc('month', now() - interval '12 month', 'utc'), 6::bigint)
           $$)
         end;
  -- an end time that is before the start time will yield no results.
  select case when test_is_not_same_month('yesterday'::timestamptz, now())
         then skip('certain tests don''t work on the first day of the month', 1)
         else is_empty(
           $$
           select * from hcp_billing_monthly_active_users_all(date_trunc('month', now() - interval '2 month', 'utc'),
                                                              date_trunc('month', now() - interval '5 month', 'utc'));
           $$)
         end;

  select * from finish();
rollback;
