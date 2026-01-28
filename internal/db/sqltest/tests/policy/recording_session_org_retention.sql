-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(18);

  select has_table('recording_session');
  select has_column('recording_session', 'retain_for_days');
  select has_column('recording_session', 'retain_until');
  select has_column('recording_session', 'delete_after_days');
  select has_column('recording_session', 'delete_after');
  select has_column('recording_session', 'delete_time');

  -- test value-setting triggers

  -- no endtime, retain_until and delete_after should be null
  insert into recording_session
    (public_id,      storage_bucket_id, session_id,     target_org_id, retain_for_days, delete_after_days)
  values
    ('sr_________1',    'sb____global', 's2_____carly', 'o_____colors',             10,                10);
  select results_eq('select retain_until, delete_after from recording_session where public_id = ''sr_________1''',
    $$VALUES (null::rec_timestamp, null::rec_timestamp) $$, 'null end time should yield null retain_until and delete_after values');

  -- update endtime, retain_until and delete_after both positive
  update recording_session set end_time = '2024-01-01 12:34:56.789+00' where public_id = 'sr_________1';
  select results_eq('select retain_until, delete_after from recording_session where public_id = ''sr_________1''',
    $$VALUES ('2024-01-11 12:34:56.789+00'::rec_timestamp, '2024-01-11 12:34:56.789+00'::rec_timestamp) $$, 'populated end time should correctly calc retain_until and delete_after values');

  -- set delete_time at retain until
  update recording_session set delete_time = retain_until where public_id = 'sr_________1';
  select results_eq('select delete_time from recording_session where public_id = ''sr_________1''',
    ARRAY['2024-01-11 12:34:56.789+00'::rec_timestamp], 'delete time must be able to be set to retain_until');
  update recording_session set delete_time = null where public_id = 'sr_________1';  -- reset delete time

  -- set delete_time after retain until
  update recording_session set delete_time = '2024-01-23 12:34:56.789+00' where public_id = 'sr_________1';
  select results_eq('select delete_time from recording_session where public_id = ''sr_________1''',
    ARRAY['2024-01-23 12:34:56.789+00'::rec_timestamp], 'delete time must be able to be set after retain_until');
  update recording_session set delete_time = null where public_id = 'sr_________1';  -- reset delete time

  -- set delete_time with null retain until
  update recording_session set retain_for_days = 0, delete_time = '2024-01-11 12:34:56.789+00' where public_id = 'sr_________1';
  select results_eq('select delete_time from recording_session where public_id = ''sr_________1''',
    ARRAY['2024-01-11 12:34:56.789+00'::rec_timestamp], 'delete time must be able to be set with null retain_until');  -- TODO: is this logic correct? should we add a check to disallow this?
  update recording_session set delete_time = null where public_id = 'sr_________1';  -- reset delete time

  -- update retain, negative value should generate inf retention
  update recording_session set retain_for_days = -1, delete_after_days = 0 where public_id = 'sr_________1';
  select results_eq('select retain_until, delete_after from recording_session where public_id = ''sr_________1''',
    $$VALUES ('infinity'::rec_timestamp, null::rec_timestamp) $$, 'negative retain for days should calc inf value');
  -- update retain and delete, zero values should generate null retention and deletion

  -- test constraints
  prepare update_rs_delete_after_days_and_retain_for_days_zero as
    update recording_session set
      retain_for_days = 0,
      delete_after_days = 0
    where public_id = 'sr_________1';
  select throws_ok('update_rs_delete_after_days_and_retain_for_days_zero', 'P0001', null, 'delete_after_days and retain_for_days both cannot be zero');

  prepare update_rs_delete_after_days_negative as
    update recording_session set
      retain_for_days = 10,
      delete_after_days = -1
    where public_id = 'sr_________1';
  select throws_ok('update_rs_delete_after_days_negative', 23514, null, 'delete_after_days cannot be negative');

  prepare update_rs_delete_after_days_while_inf_retain as
    update recording_session set
      retain_for_days = -1,
      delete_after_days = 10
    where public_id = 'sr_________1';
  select throws_ok('update_rs_delete_after_days_while_inf_retain', 'P0001', null, 'delete_after_days must be 0 while retain_for_days is inf');

  prepare update_rs_delete_after_less_than_retain as
    update recording_session set
      retain_for_days = 6,
      delete_after_days = 5
    where public_id = 'sr_________1';
  select throws_ok('update_rs_delete_after_less_than_retain', 23514, null, 'delete_after must be greater than or equal to retain_for');

  prepare update_rs_delete_time_before_retain as
    update recording_session set
      retain_for_days = 10,
      delete_time = '2024-01-11 12:34:56.788+00'
    where public_id = 'sr_________1';
  select throws_ok('update_rs_delete_time_before_retain', 23514, null, 'delete_time must be after or equal to retain_until');

  prepare update_rs_delete_time_with_inf_retain as
    update recording_session set
      retain_for_days = -1,
      delete_time = '2077-01-11 12:34:56.789+00'
    where public_id = 'sr_________1';
  select throws_ok('update_rs_delete_time_with_inf_retain', 23514, null, 'delete_time cannot be set with inf retain');

  select * from finish();

rollback;
