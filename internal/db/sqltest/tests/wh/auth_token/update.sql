-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(20);

  -- should have an auth token for carly
  select is(count(*), 1::bigint)
    from auth_token
   where public_id = 'tok____carly';

  -- should have one fact for carly.
  select is(count(*), 1::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  -- the fact should have an access time that is less than now.
  select cmp_ok(auth_token_approximate_last_access_date_key, '<=', wh_date_key(now()))
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select cmp_ok(auth_token_approximate_last_access_time_key, '<', wh_time_key(now()))
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select cmp_ok(auth_token_approximate_last_access_time, '<', now()::wh_timestamp)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select cmp_ok(lower(auth_token_approximate_active_time_range), '<', now())
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select cmp_ok(upper(auth_token_approximate_active_time_range), '<', now())
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';

  -- update access time for carly's auth token.
  update auth_token
     set approximate_last_access_time = now()
   where public_id = 'tok____carly';

  -- should still only have one fact for carly.
  select is(count(*), 1::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  -- the fact should have an access time of now
  select is(auth_token_approximate_last_access_date_key, wh_date_key(now()))
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(auth_token_approximate_last_access_time_key, wh_time_key(now()))
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(auth_token_approximate_last_access_time, now()::wh_timestamp)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select cmp_ok(lower(auth_token_approximate_active_time_range), '<', now())
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(upper(auth_token_approximate_active_time_range), now())
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';

  -- should have an auth token for cora that is in pending status
  select is(count(*), 1::bigint)
    from auth_token
   where public_id = 'tok_____cora'
     and status    = 'auth token pending';

  -- since the auth token is pending, there should be no fact for cora.
  select is(count(*), 0::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u_______cora';

  -- updating a pending token to issued should result in a fact for cora.
  update auth_token
     set status = 'token issued'
   where public_id = 'tok_____cora';

  select is(count(*), 1::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u_______cora';
  select is(
            wh_auth_token_accumulating_fact.*,
            row('tok_____cora',
                'u_______cora', (select key from wh_user_dimension where user_id = 'u_______cora'),
                wh_date_key(now()), wh_time_key(now()), now(),
                -1, -1, 'infinity'::timestamptz,
                wh_date_key(now()), wh_time_key(now()), now(),
                tstzrange(now(), now(), '[]'),
                tstzrange(now(), 'infinity'::timestamptz, '[]'),
                1
            )::wh_auth_token_accumulating_fact
         )
    from wh_auth_token_accumulating_fact
   where user_id = 'u_______cora';

  -- should have an auth token for ciara that is in pending status
  select is(count(*), 1::bigint)
    from auth_token
   where public_id = 'tok____ciara'
     and status    = 'auth token pending';

  -- since the auth token is pending, there should be no fact for ciara.
  select is(count(*), 0::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______ciara';

  -- updating a pending token to something other than issued should not result in a fact.
  update auth_token
     set status = 'authentication failed'
   where public_id = 'tok____ciara';

  select is(count(*), 0::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______ciara';

  select * from finish();
rollback;
