-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(3);
  select wtt_load('widgets', 'iam', 'kms', 'auth');  

  -- Try to insert invalid auth_oidc_prompt value to test constraint
  prepare invalid_auth_oidc_prompt_value as
     insert into auth_oidc_prompt
     (oidc_method_id,       prompt)
     values
        ('aom___widget',    'invalid');

  select throws_ok(
    'invalid_auth_oidc_prompt_value',
    '23503',
    'insert or update on table "auth_oidc_prompt" violates foreign key constraint "auth_oidc_prompt_enm_fkey"',
    'inserting a row with invalid auth_oidc_prompt value'
  );  

  -- Insert valid valid_auth_oidc_prompt_value value to test constraint with a valid value
  prepare valid_auth_oidc_prompt_value as
     insert into auth_oidc_prompt
     (oidc_method_id,       prompt)
     values
        ('aom___widget',   'select_account');
  select lives_ok('valid_auth_oidc_prompt_value');

  select has_view('oidc_auth_method_with_value_obj', 'view for reading an oidc auth method with its associated value objects does not exist');


  select * from finish();
rollback;