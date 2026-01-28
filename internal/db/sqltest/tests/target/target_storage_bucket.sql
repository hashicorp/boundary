-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(11);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- validate the setup data
  select is(count(*), 2::bigint) from storage_plugin_storage_bucket;

 -- insert target with storage bucket as null with session recording enabled
  prepare invalid_session_recording_insert as
  insert into target_ssh
    (project_id,     public_id,      enable_session_recording, storage_bucket_id, name)
  values
    ('p____swidget', 'tssh___small', true,                     null,              'Small Widget SSH Target');
  select throws_ok('invalid_session_recording_insert', null, null, 'insert of invalid session recording state succeeded');

   -- insert target with storage bucket from an org not the parent of its project
  prepare invalid_storage_bucket_insert as
  insert into target_ssh
    (project_id,     public_id,      enable_session_recording, storage_bucket_id, name)
  values
    ('p____swidget', 'tssh___small', false,                    'sb____colors',    'Small Widget SSH Target');
  select throws_ok('invalid_storage_bucket_insert', null, null, 'insert of invalid storage bucket state succeeded');

  -- insert targets with valid storage buckets
  insert into target_ssh
    (project_id,     public_id,      enable_session_recording, storage_bucket_id, name)
  values
    ('p____bwidget', 'tssh_____big', false,                    null,              'Big Widget SSH Target');

  select is(count(*), 1::bigint) from target_ssh where public_id = 'tssh______cb' and storage_bucket_id = 'sb____global';
  select is(count(*), 1::bigint) from target_ssh where public_id = 'tssh______cg' and storage_bucket_id = 'sb____colors';
  select is(count(*), 1::bigint) from target_ssh where public_id = 'tssh_____big' and storage_bucket_id is null;

  -- update storage bucket to null without disabling session recording
  prepare invalid_session_recording_update as
  update target_ssh
    set storage_bucket_id = null
    where public_id = 'tssh______cb';
  select throws_ok('invalid_session_recording_enabled', null, null, 'update to invalid session recording state succeeded');

  prepare valid_session_recording_update as
  update target_ssh
    set storage_bucket_id = null, enable_session_recording = false
    where public_id = 'tssh______cb';
  select lives_ok('valid_session_recording_update', 'update to valid session recording state failed');

  -- Update target with storage bucket from an org not the parent of its project
  prepare invalid_storage_bucket_update as
  update target_ssh
    set storage_bucket_id = 'sb____colors'
    where public_id = 'tssh_____big';
  select throws_ok('invalid_storage_bucket_update', null, null, 'update to invalid storage bucket state succeeded');

  -- update storage bucket to global scope
  prepare valid_storage_bucket_global_update as
  update target_ssh
    set storage_bucket_id = 'sb____global'
    where public_id = 'tssh______cr';
  select lives_ok('valid_storage_bucket_global_update', 'update to valid storage bucket state failed');

  -- disable session recording without removing storage bucket
  prepare valid_disable_session_recording as
  update target_ssh
    set enable_session_recording = false
    where public_id = 'tssh______cr';
  select lives_ok('valid_disable_session_recording', 'update to valid storage bucket state failed');

  select * from finish();
rollback;
