-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(14);

  -- should have an auth token for carly
  select is(count(*), 1::bigint)
    from auth_token
   where public_id = 'tok____carly';

  -- should have one fact for carly.
  select is(count(*), 1::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  -- the fact should not have a deleted time.
  select is(auth_token_deleted_date_key, -1)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(auth_token_deleted_time_key, -1)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(auth_token_deleted_time, 'infinity'::wh_timestamp)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(upper(auth_token_valid_time_range), 'infinity'::timestamptz)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';

  -- Now delete the auth token and confirm the fact was updated properly.
  delete
    from auth_token
   where public_id = 'tok____carly';

  -- should still have one fact
  select is(count(*), 1::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  -- times should be updated to have a deleted time.
  select is(auth_token_deleted_date_key, wh_date_key(now()))
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(auth_token_deleted_time_key, wh_time_key(now()))
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(auth_token_deleted_time, now()::wh_timestamp)
    from wh_auth_token_accumulating_fact
   where user_id = 'u______carly';
  select is(upper(auth_token_valid_time_range), now())
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

  -- Now delete the pending auth token, this should not result in a fact.
  delete
    from auth_token
   where public_id = 'tok_____cora';

  select is(count(*), 0::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u_______cora';


  select * from finish();
rollback;
