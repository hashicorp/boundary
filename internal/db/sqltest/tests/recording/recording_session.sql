-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- recording_session tests the following triggers:
--    check_session_id_not_null
--    set_once_columns
-- and the following constraints:
--    end_time_null_or_after_start_time

begin;
  select plan(19);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'sessions');

  -- tests a fk column referencing a history table
  -- add 5 to the plan for each time this function is called
  create function hst_fk_column(column_name name, pk_table name) returns text
  as $$
    select * from collect_tap(
      has_column('recording_session', column_name),
      col_not_null('recording_session', column_name),
      col_type_is('recording_session', column_name, 'wt_url_safe_id'), -- should be the same type as the operational table
      col_hasnt_default('recording_session', column_name),
      fk_ok('recording_session', column_name, pk_table, 'history_id')
    );
  $$ language sql;

  -- check the recording_session scheme
  select hst_fk_column('user_scope_hst_id', 'iam_scope_hst');
  select hst_fk_column('user_hst_id', 'iam_user_hst');

  -- test insert trigger can handle more than one row of history
  -- update the iam_scope of test user 's1_____clare'
  select is(count(*), 1::bigint)
    from iam_scope_hst
   where public_id = 'p____bcolors';

  update iam_scope
     set description = 'updated description'
   where public_id = 'p____bcolors';

  select is(count(*), 2::bigint)
    from iam_scope_hst
   where public_id = 'p____bcolors';

  -- Try to insert row with null session id
  prepare insert_invalid_recording_session as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id)
    values
      ('sr_123456789', 'sb_________g',    null);
  select throws_ok('insert_invalid_recording_session', null, null, 'insert invalid recording_session succeeded');

  prepare insert_recording_session as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id)
    values
      ('sr_123456789', 'sb_________g',    's1_____clare');
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
    delete from storage_plugin_storage_bucket where public_id = 'sb_________g';
  select throws_ok('delete_bucket', null, null, 'deleting a storage_plugin_storage_bucket with recordings succeeded');

  select * from finish();
rollback;
