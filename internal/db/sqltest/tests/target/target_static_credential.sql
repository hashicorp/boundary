-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(3);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select is(count(*), 1::bigint)
    from credential_static cred
    join credential_store cs on cred.store_id = cs.public_id
   where cs.project_id  = 'p____bwidget'
     and cs.public_id = 'cs______wup1'
     and cred.public_id = 'cred____wup1';

  insert into target
    (project_id,     public_id)
  values
    ('p____bwidget', 'test______wb');

  prepare insert_valid_target_static_credential as
    insert into target_static_credential
      (project_id,     target_id,      credential_static_id, credential_purpose)
    values
      ('p____bwidget', 'test______wb', 'cred____wup1',       'brokered'),
      ('p____bwidget', 'test______wb', 'cred____wjson1',       'brokered');
  select lives_ok('insert_valid_target_static_credential', 'insert valid target_static_credential failed');

  -- create a credential_static_store and target in a different project
  insert into credential_static_store
      (project_id,     public_id,      name,                description)
    values
      ('p____swidget', 'test______cs', 'test static store', 'None');

  insert into credential_static_username_password_credential
    (store_id,       public_id,      name,                                       description, username, password_encrypted,   password_hmac, key_id)
  values
    ('test______cs', 'test____cred', 'test static username password credential', 'None',      'b_user', 'encrypted_password', 'hmac-value',  'kdkv___widget');

  prepare insert_invalid_target_static_credential as
    insert into target_static_credential
      (project_id,     target_id,      credential_static_id, credential_purpose)
    values
      ('p____bwidget', 'test______wb', 'test____cred',       'brokered');
  select throws_ok('insert_invalid_target_static_credential', '23503', null, 'insert invalid target_credential_library succeeded');

  select * from finish();
rollback;
