-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- credential_vault_store_list_lookup tests the credential_vault_store_list_lookup view

begin;

  select plan(5);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select has_view('credential_vault_store_list_lookup', 'view for list and lookup Vault stores does not exist');
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'vs_______cvs1';
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'vs_______cvs2';
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'vs_______cvs3';

  -- create test vault tokens
  insert into credential_vault_token
    (token_hmac,   token,   store_id,        last_renewal_time, expiration_time,          key_id,          status)
  values
    ('cvs_token2', 'token', 'vs_______cvs1', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'maintaining'),
    ('cvs_token1', 'token', 'vs_______cvs1', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'current'),
    ('cvs_token5', 'token', 'vs_______cvs2', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'revoke'),
    ('cvs_token4', 'token', 'vs_______cvs2', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'maintaining'),
    ('cvs_token3', 'token', 'vs_______cvs2', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired'),
    ('cvs_token8', 'token', 'vs_______cvs3', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired'),
    ('cvs_token7', 'token', 'vs_______cvs3', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired'),
    ('cvs_token6', 'token', 'vs_______cvs3', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired');

  prepare select_stores as
    select public_id::text, token_hmac, token_status::text
    from credential_vault_store_list_lookup
    where public_id in ('vs_______cvs1', 'vs_______cvs2', 'vs_______cvs3')
    order by public_id;

  select results_eq(
    'select_stores',
    $$VALUES
      ('vs_______cvs1', 'cvs_token1'::bytea, 'current'),
      ('vs_______cvs2', null,                'expired'),
      ('vs_______cvs3', null,                'expired')$$
  );

  select * from finish();

rollback;
