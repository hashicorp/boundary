-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- credential_vault_library_issue_credentials tests the credential_vault_library_issue_credentials view

begin;

  select plan(9);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select has_view('credential_vault_library_issue_credentials', 'view for issuing credentials does not exist');
  select is(count(*), 1::bigint) from credential_vault_store where public_id = 'vs_______wvs';

  select is(count(*), 4::bigint)
    from credential_vault_generic_library_ssh_private_key_mapping_ovrd
   where library_id in ('vl______wvl9', 'vl______wvl10', 'vl______wvl11', 'vl______wvl12');

  select is(count(*), 4::bigint)
    from credential_vault_generic_library_username_password_mapping_ovrd
  where library_id in ('vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7');

  select is(count(*), 8::bigint)
    from credential_vault_generic_library_usern_pass_domain_mapping_ovrd
  where library_id in ('vl______wvl13', 'vl______wvl14', 'vl______wvl15', 'vl______wvl16', 'vl______wvl17', 'vl______wvl18', 'vl______wvl19', 'vl______wvl20');

  select is(count(*), 8::bigint)
    from credential_vault_generic_library_mapping_override
   where library_id in ('vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7', 'vl______wvl9', 'vl______wvl10', 'vl______wvl11', 'vl______wvl12');

  -- create test vault tokens
  insert into credential_vault_token
    (token_hmac,   token,   store_id,       last_renewal_time, expiration_time,          key_id,          status)
  values
    ('cvs_token2', 'token', 'vs_______wvs', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'maintaining'),
    ('cvs_token1', 'token', 'vs_______wvs', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'expired'),
    ('cvs_token3', 'token', 'vs_______wvs', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'current');

  prepare select_libraries as
    select public_id::text, token_hmac, token_status::text, credential_type::text, username_attribute::text, password_attribute::text, private_key_attribute::text, private_key_passphrase_attribute::text
    from credential_vault_library_issue_credentials
    where public_id in ('vl______wvl2', 'vl______wvl3', 'vl______wvl4', 'vl______wvl5', 'vl______wvl6', 'vl______wvl7', 'vl______wvl8', 'vl______wvl9', 'vl______wvl10', 'vl______wvl11', 'vl______wvl12')
    order by public_id;

  select results_eq(
    'select_libraries',
    $$VALUES
      ('vl______wvl10', 'cvs_token3'::bytea, 'current', 'ssh_private_key',   'my_username', null,          null,             null),
      ('vl______wvl11', 'cvs_token3'       , 'current', 'ssh_private_key',   null,          null,          'my_private_key', null),
      ('vl______wvl12', 'cvs_token3'       , 'current', 'ssh_private_key',   'my_username', null,          'my_private_key', 'my_passphrase'),
      ('vl______wvl2',  'cvs_token3'       , 'current', 'unspecified',       null,          null,          null,             null),
      ('vl______wvl3',  'cvs_token3'       , 'current', 'username_password', null,          null,          null,             null),
      ('vl______wvl4',  'cvs_token3'       , 'current', 'username_password', null,          null,          null,             null),
      ('vl______wvl5',  'cvs_token3'       , 'current', 'username_password', 'my_username', null,          null,             null),
      ('vl______wvl6',  'cvs_token3'       , 'current', 'username_password', null,          'my_password', null,             null),
      ('vl______wvl7',  'cvs_token3'       , 'current', 'username_password', 'my_username', 'my_password', null,             null),
      ('vl______wvl8',  'cvs_token3'       , 'current', 'ssh_private_key',   null,          null,          null,             null),
      ('vl______wvl9',  'cvs_token3'       , 'current', 'ssh_private_key',   null,          null,          null,             null)$$
  );

  -- create a new current token
  insert into credential_vault_token
    (token_hmac,   token,   store_id,       last_renewal_time, expiration_time,          key_id,          status)
  values
    ('cvs_token4', 'token', 'vs_______wvs', now(),             wt_add_seconds_to_now(1), 'kdkv___widget', 'current');

  select results_eq(
    'select_libraries',
    $$VALUES
      ('vl______wvl10', 'cvs_token4'::bytea, 'current', 'ssh_private_key',   'my_username', null,          null,             null),
      ('vl______wvl11', 'cvs_token4'       , 'current', 'ssh_private_key',   null,          null,          'my_private_key', null),
      ('vl______wvl12', 'cvs_token4'       , 'current', 'ssh_private_key',   'my_username', null,          'my_private_key', 'my_passphrase'),
      ('vl______wvl2',  'cvs_token4'       , 'current', 'unspecified',       null,          null,          null,             null),
      ('vl______wvl3',  'cvs_token4'       , 'current', 'username_password', null,          null,          null,             null),
      ('vl______wvl4',  'cvs_token4'       , 'current', 'username_password', null,          null,          null,             null),
      ('vl______wvl5',  'cvs_token4'       , 'current', 'username_password', 'my_username', null,          null,             null),
      ('vl______wvl6',  'cvs_token4'       , 'current', 'username_password', null,          'my_password', null,             null),
      ('vl______wvl7',  'cvs_token4'       , 'current', 'username_password', 'my_username', 'my_password', null,             null),
      ('vl______wvl8',  'cvs_token4'       , 'current', 'ssh_private_key',   null,          null,          null,             null),
      ('vl______wvl9',  'cvs_token4'       , 'current', 'ssh_private_key',   null,          null,          null,             null)$$
  );

  -- expire token
  update credential_vault_token
    set status = 'expired'
  where token_hmac = 'cvs_token4';

  select results_eq(
    'select_libraries',
    $$VALUES
      ('vl______wvl10', null::bytea, 'expired', 'ssh_private_key',   'my_username', null,          null,             null),
      ('vl______wvl11', null       , 'expired', 'ssh_private_key',   null,          null,          'my_private_key', null),
      ('vl______wvl12', null       , 'expired', 'ssh_private_key',   'my_username', null,          'my_private_key', 'my_passphrase'),
      ('vl______wvl2',  null       , 'expired', 'unspecified',       null,          null,          null,             null),
      ('vl______wvl3',  null       , 'expired', 'username_password', null,          null,          null,             null),
      ('vl______wvl4',  null       , 'expired', 'username_password', null,          null,          null,             null),
      ('vl______wvl5',  null       , 'expired', 'username_password', 'my_username', null,          null,             null),
      ('vl______wvl6',  null       , 'expired', 'username_password', null,          'my_password', null,             null),
      ('vl______wvl7',  null       , 'expired', 'username_password', 'my_username', 'my_password', null,             null),
      ('vl______wvl8',  null       , 'expired', 'ssh_private_key',   null,          null,          null,             null),
      ('vl______wvl9',  null       , 'expired', 'ssh_private_key',   null,          null,          null,             null)$$
  );

  select * from finish();

rollback;
