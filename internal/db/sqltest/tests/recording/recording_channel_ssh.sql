-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- recording_channel_ssh tests the following triggers:
--    insert_recording_channel_subtype
--    delete_recording_channel_subtype
-- and the following constraints:
--    end_time_null_or_after_start_time
--    bytes_up_null_zero_or_positive
--    bytes_down_null_zero_or_positive
--    subsystem_shorter_than_1024_bytes

begin;
  select plan(14);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'sessions');

  select has_view('recording_channel_ssh_aggregate', 'view for aggregating channel recording info does not exist');

  insert into recording_session
    (public_id,      storage_bucket_id, session_id,     state,     target_org_id)
  values
    ('sr_123456789', 'sb____global',    's2_____clare', 'started', 'o_____colors');
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
      ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz - '1s'::interval, 10,       10,         'x11');
  select throws_ok('end_time_before_start_time', '23514', null, 'inserting a row with end_time before star_time succeeded');

  -- Try to set bytes_up to a negative number
  prepare negative_bytes_up as
    insert into recording_channel_ssh
      (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
    values
      ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, -1,       10,         'x11');
  select throws_ok('negative_bytes_up', '23514', null, 'inserting a row with a negative bytes_up value succeeded');

  -- Try to set bytes_down to a negative number
  prepare negative_bytes_down as
    insert into recording_channel_ssh
      (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
    values
      ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       -1,         'x11');
  select throws_ok('negative_bytes_down', '23514', null, 'inserting a row with a negative bytes_down value succeeded');

  -- Check that there are no rows
  select is(count(*), 0::bigint) from recording_channel_ssh;
  select is(count(*), 0::bigint) from recording_channel;

  insert into recording_channel_ssh
    (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
  values
    ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),--    'none',       null,         null),
    ('chr_234567891', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),--    'shell',         null,         null),
    ('chr_345678912', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),--    'exec',          'scp',        null),
    ('chr_456789123', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),--    'subsystem',     null,         'sftp'),
    ('chr_567891234', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'x11');--,        null,            null,         null);

  insert into recording_channel_ssh_session_channel
    (recording_channel_id, program)
  values
    ('chr_123456789',      'none'),
    ('chr_234567891',      'shell'),
    ('chr_345678912',      'exec'),
    ('chr_456789123',      'subsystem');
  
  insert into recording_channel_ssh_session_channel_program_exec
    (recording_channel_id, exec_program)
  values
    ('chr_345678912', 'scp');

  -- Try to insert a large subsystem row
    prepare insert_large_subsystem_name as
      insert into recording_channel_ssh_session_channel_program_subsystem
        (recording_channel_id, subsystem_name)
      values
        ('chr_456789123', repeat('sftp', 1000));
    select throws_ok('insert_large_subsystem_name', '23514', null, 'inserting a large subsystem_name succeeded');


  insert into recording_channel_ssh_session_channel_program_subsystem
    (recording_channel_id, subsystem_name)
  values
    ('chr_456789123', 'sftp');

  prepare select_session_recordings as
    select public_id::text, recording_connection_id::text, bytes_up::int, bytes_down::int,
           channel_type::text, channel_program::text
    from recording_channel_ssh_aggregate
    order by public_id;

  select results_eq(
    'select_session_recordings',
    $$VALUES
      ('chr_123456789', 'cr_123456789', 10, 10, 'session', 'none'),
      ('chr_234567891', 'cr_123456789', 10, 10, 'session', 'shell'),
      ('chr_345678912', 'cr_123456789', 10, 10, 'session', 'exec'),
      ('chr_456789123', 'cr_123456789', 10, 10, 'session', 'subsystem'),
      ('chr_567891234', 'cr_123456789', 10, 10, 'x11', null)$$
         );

  -- Check that the rows were inserted
  select is(count(*), 5::bigint) from recording_channel_ssh where recording_connection_id = 'cr_123456789';
  select is(count(*), 5::bigint) from recording_channel where recording_connection_id = 'cr_123456789';

  -- Deleting the session connection should leave the recording in place
  delete from session_connection where public_id = 'sc_123456789';
  -- Row should still be present
  select is(count(*), 5::bigint) from recording_channel_ssh where recording_connection_id = 'cr_123456789';

  -- Deleting the session should leave the recording in place
  delete from session where public_id = 's2_____clare';
  -- Row should still be present
  select is(count(*), 5::bigint) from recording_channel_ssh where recording_connection_id = 'cr_123456789';

  -- Deleting the session recording should cascade to the channel recording
  delete from recording_session where public_id = 'sr_123456789';
  -- Row should be deleted
  select is(count(*), 0::bigint) from recording_channel_ssh where recording_connection_id = 'cr_123456789';

  -- Check that it was also deleted from recording_channel
  select is(count(*), 0::bigint) from recording_channel;

  select * from finish();
rollback;
