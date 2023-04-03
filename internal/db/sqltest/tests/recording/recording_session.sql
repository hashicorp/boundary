-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- recording_session tests the following triggers:
--    check_session_id_not_null
--    set_once_columns
-- and the following constraints:
--    end_time_null_or_after_start_time

begin;
  select plan(7);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'sessions');
  
  insert into storage_bucket (public_id, scope_id) values ('sb_123456789', 'global');

  -- Try to insert row with null session id
  prepare insert_invalid_recording_session as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id)
    values
      ('sr_123456789', 'sb_123456789',    null);
  select throws_ok('insert_invalid_recording_session', null, null, 'insert invalid recording_session succeeded');

  prepare insert_recording_session as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id)
    values
      ('sr_123456789', 'sb_123456789',    's1_____clare');
  select lives_ok('insert_recording_session');

  -- Try to set end_time before start_time
  prepare invalid_close_recording_session as
    update recording_session set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz - '1s'::interval
    where public_id = 'sr_123456789';
  select throws_ok('invalid_close_recording_session', '23514', null, 'setting end_time before start_time succeeded');

  prepare close_recording_session as
    update recording_session set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz + '1s'::interval
    where public_id = 'sr_123456789';
  select lives_ok('close_recording_session');

  -- Closing a second time should error
  select throws_ok('close_recording_session', '23602', null, 'closing a recording_session twice succeeded');

  -- Deleting the session should leave the recording in place
  delete from session where public_id = 's1_____clare';
  -- Row should still be present
  select is(count(*), 1::bigint) from recording_session where public_id = 'sr_123456789';

  -- Deleting the storage bucket with active recordings should fail
  prepare delete_bucket as
    delete from storage_bucket where public_id = 'sb_123456789';
  select throws_ok('delete_bucket', null, null, 'deleting a storage_bucket with recordings succeeded');

  select * from finish();
rollback;
