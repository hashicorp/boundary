-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- credential_vault_store_client tests the credential_vault_store_client view

begin;

  select plan(5);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select has_view('credential_vault_store_client', 'view for client Vault stores does not exist');
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'cvs__bcolors';
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'cvs__rcolors';
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'cvs__gcolors';

  -- create test vault tokens
  insert into credential_vault_token
    (token_hmac,   token,   store_id,       last_renewal_time, expiration_time,          key_id,          status)
  values
    ('cvs_token2', 'token', 'cvs__bcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'maintaining'),
    ('cvs_token1', 'token', 'cvs__bcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'current'),
    ('cvs_token5', 'token', 'cvs__rcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'revoke'),
    ('cvs_token4', 'token', 'cvs__rcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'maintaining'),
    ('cvs_token3', 'token', 'cvs__rcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired'),
    ('cvs_token8', 'token', 'cvs__gcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired'),
    ('cvs_token7', 'token', 'cvs__gcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired'),
    ('cvs_token6', 'token', 'cvs__gcolors', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired');

  prepare select_stores as
    select public_id::text, token_hmac, token_status::text
    from credential_vault_store_client
    where public_id in ('cvs__bcolors', 'cvs__rcolors', 'cvs__gcolors')
    order by public_id, token_hmac;

  select results_eq(
    'select_stores',
    $$VALUES
      ('cvs__bcolors', 'cvs_token1'::bytea, 'current'),
      ('cvs__gcolors', null,                'expired'),
      ('cvs__rcolors', null,                'expired')$$
  );

  select * from finish();

rollback;
