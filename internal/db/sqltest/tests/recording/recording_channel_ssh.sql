-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- recording_channel_ssh tests the following triggers:
--    insert_recording_channel_subtype
--    delete_recording_channel_subtype
-- and the following constraints:
--    end_time_null_or_after_start_time
--    bytes_up_null_zero_or_positive
--    bytes_down_null_zero_or_positive

begin;
  select plan(9);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'sessions');

  insert into recording_session
    (public_id,      storage_bucket_id, session_id)
  values
    ('sr_123456789', 'sb____global',    's2_____clare');
  insert into session_connection
    (public_id,      session_id)
  values
    ('sc_123456789', 's2_____clare');
  insert into recording_connection
    (public_id,      session_id,     session_connection_id, recording_session_id)
  values
    ('cr_123456789', 's2_____clare', 'sc_123456789',        'sr_123456789');

  -- Try to set end_time before start_time
  prepare end_time_before_start_time as
    insert into recording_channel_ssh
      (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
    values
      ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz - '1s'::interval, 10,       10,         'session');
  select throws_ok('end_time_before_start_time', '23514', null, 'inserting a row with end_time before star_time succeeded');

  -- Try to set bytes_up to a negative number
  prepare negative_bytes_up as
    insert into recording_channel_ssh
      (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
    values
      ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, -1,       10,         'session');
  select throws_ok('negative_bytes_up', '23514', null, 'inserting a row with a negative bytes_up value succeeded');

  -- Try to set bytes_down to a negative number
  prepare negative_bytes_down as
    insert into recording_channel_ssh
      (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
    values
      ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       -1,         'session');
  select throws_ok('negative_bytes_down', '23514', null, 'inserting a row with a negative bytes_down value succeeded');

  -- Check that there are no rows
  select is(count(*), 0::bigint) from recording_channel;

  insert into recording_channel_ssh
    (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
  values
    ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session');

  -- Check that a row was inserted
  select is(count(*), 1::bigint) from recording_channel where public_id = 'chr_123456789' and recording_connection_id = 'cr_123456789';

  -- Deleting the session connection should leave the recording in place
  delete from session_connection where public_id = 'sc_123456789';
  -- Row should still be present
  select is(count(*), 1::bigint) from recording_channel where public_id = 'chr_123456789';

  -- Deleting the session should leave the recording in place
  delete from session where public_id = 's2_____clare';
  -- Row should still be present
  select is(count(*), 1::bigint) from recording_channel where public_id = 'chr_123456789';

  -- Deleting the session recording should cascade to the channel recording
  delete from recording_session where public_id = 'sr_123456789';
  -- Row should be deleted
  select is(count(*), 0::bigint) from recording_channel where public_id = 'chr_123456789';

  -- Check that it was also deleted from recording_channel
  select is(count(*), 0::bigint) from recording_channel;

  select * from finish();
rollback;
