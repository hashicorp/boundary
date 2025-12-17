-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- recording_connection tests the following triggers:
--    check_session_id_and_session_connection_id_not_null
--    set_once_columns
-- and the following constraints:
--    end_time_null_or_after_start_time
--    bytes_up_null_zero_or_positive
--    bytes_down_null_zero_or_positive

begin;
  select plan(10);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'sessions');

  insert into recording_session
    (public_id,      storage_bucket_id, session_id,     target_org_id)
  values
    ('sr_123456789', 'sb____global',    's2_____clare', 'o_____colors');
  insert into session_connection
    (public_id,      session_id)
  values
    ('sc_123456789', 's2_____clare');

  -- Try to insert row with null session id
  prepare insert_recording_connection_with_null_session_id as
    insert into recording_connection
      (public_id,      session_id, session_connection_id, recording_session_id)
    values
      ('cr_123456789', null,       'sc_123456789',        'sr_123456789');
  select throws_ok('insert_recording_connection_with_null_session_id', null, null, 'insert recording_connection with null session_id succeeded');

  -- Try to insert row with null session connection id
  prepare insert_recording_connection_with_null_session_connection_id as
    insert into recording_connection
      (public_id,      session_id,     session_connection_id, recording_session_id)
    values
      ('cr_123456789', 's2_____clare', null,                  'sr_123456789');
  select throws_ok('insert_recording_connection_with_null_session_connection_id', null, null, 'insert recording_connection with null session_connection_id succeeded');

  insert into recording_connection
    (public_id,      session_id,     session_connection_id, recording_session_id)
  values
    ('cr_123456789', 's2_____clare', 'sc_123456789',        'sr_123456789');

  -- Try to set end_time before start_time
  prepare set_end_time_before_start_time as
    update recording_connection set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz - '1s'::interval,
      bytes_up = 10,
      bytes_down = 10
    where public_id = 'cr_123456789';
  select throws_ok('set_end_time_before_start_time', '23514', null, 'setting an end_time before the start_time succeeded');

  -- Try to set bytes_up to a negative number
  prepare set_negative_bytes_up as
    update recording_connection set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz + '1s'::interval,
      bytes_up = -1,
      bytes_down = 10
    where public_id = 'cr_123456789';
  select throws_ok('set_negative_bytes_up', '23514', null, 'setting a negative bytes_up value succeeded');

  -- Try to set bytes_down to a negative number
  prepare set_negative_bytes_down as
    update recording_connection set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz + '1s'::interval,
      bytes_up = 10,
      bytes_down = -1
    where public_id = 'cr_123456789';
  select throws_ok('set_negative_bytes_down', '23514', null, 'setting a negative bytes_down value succeeded');

  prepare close_recording_connection as
    update recording_connection set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz + '1s'::interval,
      bytes_up = 10,
      bytes_down = 10
    where public_id = 'cr_123456789';
  select lives_ok('close_recording_connection');

  -- Closing again should fail
  select throws_ok('close_recording_connection', '23602', null, 'closing a recording_connection twice succeeded');

  -- Deleting the session connection should leave the recording in place
  delete from session_connection where public_id = 'sc_123456789';
  -- Row should still be present
  select is(count(*), 1::bigint) from recording_connection where public_id = 'cr_123456789';

  -- Deleting the session should leave the recording in place
  delete from session where public_id = 's2_____clare';
  -- Row should still be present
  select is(count(*), 1::bigint) from recording_connection where public_id = 'cr_123456789';

  -- Deleting the session recording should cascade to the connection recording
  delete from recording_session where public_id = 'sr_123456789';
  -- Row should be deleted
  select is(count(*), 0::bigint) from recording_connection where public_id = 'cr_123456789';

  select * from finish();
rollback;
