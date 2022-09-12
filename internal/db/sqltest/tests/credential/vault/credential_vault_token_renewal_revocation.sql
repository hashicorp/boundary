-- credential_vault_token_renewal_revocation tests the credential_vault_token_renewal_revocation view

begin;

  select plan(5);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select has_view('credential_vault_token_renewal_revocation', 'view for renewal/revocation Vault stores does not exist');
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
    from credential_vault_token_renewal_revocation
    where public_id in ('vs_______cvs1', 'vs_______cvs2', 'vs_______cvs3')
    order by public_id, token_hmac;

  select results_eq(
    'select_stores',
    $$VALUES
      ('vs_______cvs1', 'cvs_token1'::bytea, 'current'),
      ('vs_______cvs1', 'cvs_token2'::bytea, 'maintaining'),
      ('vs_______cvs2', 'cvs_token4'::bytea, 'maintaining'),
      ('vs_______cvs2', 'cvs_token5'::bytea, 'revoke')$$
  );

  select * from finish();

rollback;
