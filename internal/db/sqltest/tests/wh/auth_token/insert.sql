-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms');

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

  -- Create auth method and account to use for making auth tokens.
  insert into auth_password_conf
    (password_method_id, private_id)
  values
    ('apm___widget', 'apmc__widget');
  insert into auth_password_method
    (scope_id, public_id, password_conf_id, name)
  values
    ('o_____widget', 'apm___widget', 'apmc__widget', 'Widget Auth Password');
  insert into auth_password_account
    (auth_method_id, public_id, login_name)
  values
    ('apm___widget', 'apa___walter', 'walter');
  update auth_account set iam_user_id = 'u_____walter' where public_id = 'apa___walter';

  -- should start with no facts for this user.
  select is(count(*), 0::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u_____walter';

  -- Insert with status 'auth token pending' should not create a auth token fact.
  insert into auth_token
    (key_id,          auth_account_id, public_id,       token,                  status)
  values
    ('kdkv___widget', 'apa___walter',  'tok___walter1', 'tok___walter1'::bytea, 'auth token pending');
  select is(count(*), 0::bigint) from wh_auth_token_accumulating_fact where user_id = 'u_____walter';

  -- Insert an auth token wuth the 'token issued' status.
  insert into auth_token
    (key_id,          auth_account_id, public_id,       token,                  status)
  values
    ('kdkv___widget', 'apa___walter',  'tok___walter2', 'tok___walter2'::bytea, 'token issued');

  -- should have one fact for this user.
  select is(count(*), 1::bigint)
    from wh_auth_token_accumulating_fact
   where user_id = 'u_____walter';
  select is(
            wh_auth_token_accumulating_fact.*,
            row('tok___walter2',
                'u_____walter', (select key from wh_user_dimension where user_id = 'u_____walter'),
                wh_date_key(now()), wh_time_key(now()), now(),
                -1, -1, 'infinity'::timestamptz,
                wh_date_key(now()), wh_time_key(now()), now(),
                tstzrange(now(), now(), '[]'),
                tstzrange(now(), 'infinity'::timestamptz, '[]'),
                1
            )::wh_auth_token_accumulating_fact
         )
    from wh_auth_token_accumulating_fact
   where user_id = 'u_____walter';

  select * from finish();
rollback;
