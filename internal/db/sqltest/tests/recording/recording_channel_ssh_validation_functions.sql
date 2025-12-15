-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- recording_channel_ssh_validation_functions tests the following functions:
--    validate_recording_channel_ssh_insert
--    validate_recording_channel_ssh_session_channel_insert
--    validate_recording_channel_ssh_subsystem_insert
--    validate_recording_channel_ssh_exec_insert

begin;
  select plan(14);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'sessions');

  insert into recording_connection
    (public_id,      session_id,     session_connection_id, recording_session_id)
  values
    ('cr_123456789', 's1_____clare', 's1c1___clare',        'sr1____clare');
  insert into recording_channel_ssh
    (public_id,       recording_connection_id, start_time,                     end_time,                                        bytes_up, bytes_down, channel_type)
  values
    ('chr_123456789', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),
    ('chr_234567891', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),
    ('chr_345678912', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),
    ('chr_456789123', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'session'),
    ('chr_567891234', 'cr_123456789',          clock_timestamp()::timestamptz, clock_timestamp()::timestamptz + '1s'::interval, 10,       10,         'x11');
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
  insert into recording_channel_ssh_session_channel_program_subsystem
    (recording_channel_id, subsystem_name)
  values
    ('chr_456789123', 'sftp');

  ---
  -- validate_recording_channel_ssh_insert tests
  ----
  -- Validate the valid row with id chr_123456789
  prepare valid_session_channel_passes as
    select validate_recording_channel_ssh_insert('session', 'chr_123456789');
  select lives_ok('valid_session_channel_passes');

  -- Validate the valid non-session row with id chr_567891234
  prepare non_session_channel_passes as
    select validate_recording_channel_ssh_insert('x11', 'chr_567891234');
  select lives_ok('non_session_channel_passes');

  -- Should error when pretending chr_567891234 is a session channel,
  -- since there is no corresponding row in recording_channel_ssh_session_channel
  prepare invalid_session_channel_fails as
    select validate_recording_channel_ssh_insert('session', 'chr_567891234');
  select throws_ok('invalid_session_channel_fails', null, 'Channel recording of type ''session'' must populate recording_channel_ssh_session_channel');

  ---
  -- validate_recording_channel_ssh_session_channel_insert tests
  ----
  -- Validate the valid row with id chr_123456789
  prepare valid_session_channel_insert_none_passes as
    select validate_recording_channel_ssh_session_channel_insert('chr_123456789', 'none');
  select lives_ok('valid_session_channel_insert_none_passes');

  -- Validate the valid row with id chr_234567891
  prepare valid_session_channel_insert_shell_passes as
    select validate_recording_channel_ssh_session_channel_insert('chr_234567891', 'shell');
  select lives_ok('valid_session_channel_insert_shell_passes');

  -- Validate the valid row with id chr_345678912
  prepare valid_session_channel_insert_exec_passes as
    select validate_recording_channel_ssh_session_channel_insert('chr_345678912', 'exec');
  select lives_ok('valid_session_channel_insert_exec_passes');

  -- Validate the valid row with id chr_456789123
  prepare valid_session_channel_insert_subsystem_passes as
    select validate_recording_channel_ssh_session_channel_insert('chr_456789123', 'subsystem');
  select lives_ok('valid_session_channel_insert_subsystem_passes');

  -- Should error when pretending chr_123456789 is a subsystem program,
  -- since there is no corresponding row in recording_channel_ssh_session_channel_program_subsystem
  prepare invalid_session_channel_subsystem_fails as
    select validate_recording_channel_ssh_session_channel_insert('chr_123456789', 'subsystem');
  select throws_ok('invalid_session_channel_subsystem_fails', null, 'Session channel with program ''exec'' must populate recording_channel_ssh_session_channel_program_exec');

  -- Should error when pretending chr_123456789 is an exec program,
  -- since there is no corresponding row in recording_channel_ssh_session_channel_program_exec
  prepare invalid_session_channel_exec_fails as
    select validate_recording_channel_ssh_session_channel_insert('chr_123456789', 'exec');
  select throws_ok('invalid_session_channel_exec_fails', null, 'Session channel with program ''subsystem'' must populate recording_channel_ssh_session_channel_program_subsystem');

  -- Should error when using the non-session channel chr_567891234,
  -- as it doesn't have the channel_type session.
  prepare non_session_channel_id_fails as
    select validate_recording_channel_ssh_session_channel_insert('chr_567891234', 'none');
  select throws_ok('non_session_channel_id_fails', null, 'Session channel must have channel_type ''session''');

  ---
  -- validate_recording_channel_ssh_subsystem_insert tests
  ----
  -- Validate the valid row with id chr_456789123
  prepare valid_session_channel_subsystem_insert_passes as
    select validate_recording_channel_ssh_subsystem_insert('chr_456789123');
  select lives_ok('valid_session_channel_subsystem_insert_passes');
  
  -- Should error when using the non-subsystem session channel chr_123456789,
  -- as it doesn't have the program subsystem.
  prepare non_subsystem_session_channel_id_fails as
    select validate_recording_channel_ssh_subsystem_insert('chr_123456789');
  select throws_ok('non_subsystem_session_channel_id_fails', null, 'Session channel subsystem program must have program ''subsystem''');

  ---
  -- validate_recording_channel_ssh_exec_insert tests
  ----
  -- Validate the valid row with id chr_345678912
  prepare valid_session_channel_exec_insert_passes as
    select validate_recording_channel_ssh_exec_insert('chr_345678912');
  select lives_ok('valid_session_channel_exec_insert_passes');
  
  -- Should error when using the non-exec session channel chr_123456789,
  -- as it doesn't have the program exec.
  prepare non_exec_session_channel_id_fails as
    select validate_recording_channel_ssh_exec_insert('chr_123456789');
  select throws_ok('non_exec_session_channel_id_fails', null, 'Session channel exec program must have program ''exec''');

  select * from finish();
rollback;
