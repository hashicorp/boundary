-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(9);

  -- check view
  -- no endtime, view should be fine
  insert into recording_session
    (public_id,      storage_bucket_id, session_id,     target_org_id, retain_for_days, delete_after_days)
  values
    ('sr_________1',    'sb____global', 's2_____clare', 'o_____colors',             10,                10);
  select results_eq('select public_id from session_recording_aggregate where public_id = ''sr_________1''',
    ARRAY['sr_________1'::wt_public_id], 'null delete_after and delete_time allows session_recording_aggregate to return session_recording');

  -- update endtime to something impossibly large
  update recording_session set end_time = '3000-01-23 12:34:56.789+00' where public_id = 'sr_________1';
  -- check to make sure the view where clause works correctly
  select results_eq('select public_id from session_recording_aggregate where public_id = ''sr_________1''',
    ARRAY['sr_________1'::wt_public_id], 'future delete_after allows session_recording_aggregate to return session_recording');

  -- update delete_time to something equally large
  update recording_session set delete_time = retain_until where public_id = 'sr_________1';
  -- check to make sure the view where clause works correctly
  select results_eq('select public_id from session_recording_aggregate where public_id = ''sr_________1''',
    ARRAY['sr_________1'::wt_public_id], 'future delete_after and delete_time allows session_recording_aggregate to return session_recording');

  -- no endtime, view should be fine
  insert into recording_session
    (public_id,      storage_bucket_id, session_id,     target_org_id, retain_for_days, delete_after_days)
  values
    ('sr_________2',    'sb____global', 's2______cora', 'o_____colors',             10,                10);
  select results_eq('select public_id from session_recording_aggregate where public_id = ''sr_________2''',
    ARRAY['sr_________2'::wt_public_id], 'null delete_after and delete_time allows session_recording_aggregate to return session_recording');

  -- update endtime to something already past
  update recording_session set end_time = '2000-01-23 12:34:56.789+00' where public_id = 'sr_________2';
  -- check to make sure the view where clause works correctly
  select results_eq('select count(public_id) from session_recording_aggregate where public_id = ''sr_________2''',
    ARRAY[0::bigint], 'past delete_after makes session_recording_aggregate omit session_recording');

  -- update delete after to something in the future
  update recording_session set delete_time = '3000-01-23 12:34:56.789+00' where public_id = 'sr_________2';
  -- check to make sure the view where clause works correctly
  select results_eq('select count(public_id) from session_recording_aggregate where public_id = ''sr_________2''',
    ARRAY[0::bigint], 'past delete_after with future delete_time, session_recording_aggregate still omits session_recording');

  -- no endtime, view should be fine (notice the 0 retain_for)
  insert into recording_session
    (public_id,      storage_bucket_id, session_id,     target_org_id, retain_for_days, delete_after_days)
  values
    ('sr_________3',    'sb____global', 's2_____carly', 'o_____colors',              0,                10);
  select results_eq('select public_id from session_recording_aggregate where public_id = ''sr_________3''',
    ARRAY['sr_________3'::wt_public_id], 'null delete_after and delete_time allows session_recording_aggregate to return session_recording');

  -- update endtime to now
  update recording_session set end_time = now() where public_id = 'sr_________3';
  -- check to make sure the view where clause works correctly
  select results_eq('select public_id from session_recording_aggregate where public_id = ''sr_________3''',
    ARRAY['sr_________3'::wt_public_id], 'future delete_after allows session_recording_aggregate to return session_recording');

  -- update delete time to now
  update recording_session set delete_time = now() where public_id = 'sr_________3';
  -- check to make sure the view where clause works correctly
  select results_eq('select count(public_id) from session_recording_aggregate where public_id = ''sr_________3''',
    ARRAY[0::bigint], 'future delete_after with past delete_time, session_recording_aggregate omits session_recording correctly');

  select * from finish();

rollback;
