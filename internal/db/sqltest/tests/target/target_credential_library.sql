-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(3);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate the setup data
  select is(count(*), 1::bigint)
    from credential_library cl
    join credential_store cs on cl.store_id = cs.public_id
   where cs.project_id  = 'p____bwidget'
     and cs.public_id = 'vs_______wvs'
     and cl.public_id = 'vl______wvl1';

  insert into target
    (project_id,     public_id)
  values
    ('p____bwidget', 'test______wb');

  prepare insert_valid_target_credential_library as
    insert into target_credential_library
      (project_id,     target_id,      credential_library_id, credential_purpose)
    values
      ('p____bwidget', 'test______wb', 'vl______wvl1',        'brokered');
  select lives_ok('insert_valid_target_credential_library', 'insert valid target_credential_library failed');

  -- create a credential_store and credential_library in a different project
  insert into credential_store
    (project_id,     public_id)
  values
    ('p____swidget', 'test______cs');

  insert into credential_library
    (project_id,     store_id,       public_id,      credential_type)
  values
    ('p____swidget', 'test______cs', 'test______cl', 'unspecified');

  prepare insert_invalid_target_credential_library as
    insert into target_credential_library
      (project_id,     target_id,      credential_library_id, credential_purpose)
    values
      ('p____bwidget', 'test______wb', 'test______cl',        'brokered');
  select throws_ok('insert_invalid_target_credential_library', '23503', null, 'insert invalid target_credential_library succeeded');

  select * from finish();
rollback;
