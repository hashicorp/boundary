-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(11);
  select wtt_load('widgets', 'iam', 'kms', 'auth');

  -- Set a valid provider_type on the widget oidc auth method
  prepare valid_provider_type as
    update auth_oidc_method
    set provider_type = 'azure'
    where public_id = 'aom___widget';
  select lives_ok('valid_provider_type', 'azure is a valid provider_type');

  select is(provider_type, 'azure', 'provider_type should be azure')
    from auth_oidc_method
    where public_id = 'aom___widget';

  -- Set a provider_type that is not in the enum table
  prepare invalid_provider_type as
    update auth_oidc_method
    set provider_type = 'unsupported'
    where public_id = 'aom___widget';
  select throws_ok(
    'invalid_provider_type',
    '23503',
    'insert or update on table "auth_oidc_method" violates foreign key constraint "auth_oidc_method_provider_type_enm_fkey"',
    'setting a provider_type not in the enum table'
  );

  select is(provider_type, 'azure', 'provider_type is unchanged after a rejected update')
    from auth_oidc_method
    where public_id = 'aom___widget';

  -- Set provider_type to null
  prepare null_provider_type as
    update auth_oidc_method
    set provider_type = null
    where public_id = 'aom___widget';
  select lives_ok('null_provider_type', 'null is an allowed provider_type');

  select is(provider_type, null, 'provider_type should be null')
    from auth_oidc_method
    where public_id = 'aom___widget';

  -- Insert an unsupported value into the provider_type enum table
  prepare invalid_enum_value as
    insert into auth_oidc_method_provider_type_enm
    (name)
    values
      ('unsupported');
  select throws_ok(
    'invalid_enum_value',
    '23514',
    'new row for relation "auth_oidc_method_provider_type_enm" violates check constraint "only_predefined_auth_oidc_provider_types_allowed"',
    'inserting an unsupported value into the provider_type enum table'
  );

  -- Update an immutable provider_type enum row
  prepare immutable_enum_value as
    update auth_oidc_method_provider_type_enm
    set name = 'unsupported'
    where name = 'azure';
  select throws_ok(
    'immutable_enum_value',
    '23601',
    'immutable column: auth_oidc_method_provider_type_enm.name',
    'updating an immutable provider_type enum row'
  );

  -- validate oidc_auth_method_with_value_obj view returns provider_type
  update auth_oidc_method
    set provider_type = 'azure'
    where public_id = 'aom___widget';
  select is(provider_type, 'azure', 'the view returns the provider_type')
    from oidc_auth_method_with_value_obj
    where public_id = 'aom___widget';

  -- Reset provider_type back to null after it was set
  prepare reset_provider_type as
    update auth_oidc_method
    set provider_type = null
    where public_id = 'aom___widget';
  select lives_ok('reset_provider_type', 'provider_type can be reset to null');

  select is(provider_type, null, 'provider_type should be null after reset')
    from auth_oidc_method
    where public_id = 'aom___widget';

  select * from finish();
rollback;
