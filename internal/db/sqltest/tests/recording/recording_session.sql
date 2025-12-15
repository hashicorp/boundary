-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- recording_session tests the following triggers:
--    insert_session_recording
--    set_once_columns
--    insert_session_recording
--    update_session_recording
-- and the following constraints:
--    end_time_null_or_after_start_time

begin;
  select plan(57);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'sessions');

  select has_view('session_recording_aggregate', 'view for aggregating session recording info does not exist');

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
  select hst_fk_column('target_project_hst_id', 'iam_scope_hst');
  select hst_fk_column('target_hst_id', 'target_ssh_hst');
  select hst_fk_column('host_catalog_hst_id', 'host_catalog_history_base');
  select hst_fk_column('host_hst_id', 'host_history_base');

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

  select results_eq(
    'select host_catalog_hst_id from recording_session where public_id = ''sr1_____cora''',
    'select history_id from no_host_catalog_history');
  select results_eq(
    'select host_hst_id from recording_session where public_id = ''sr1_____cora''',
    'select history_id from no_host_history');

  select results_eq(
    'select endpoint from recording_session where public_id = ''sr1_____cora''',
    'select endpoint from session where public_id = ''s1______cora''');

  -- Try to insert row with null session id
  prepare insert_invalid_recording_session as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id, state,     target_org_id)
    values
      ('sr_________1', 'sb____global',    null,       'started', 'o_____colors');
  select throws_ok('insert_invalid_recording_session', null, null, 'insert invalid recording_session succeeded');

  -- Try to insert row with non-started state
  prepare insert_with_invalid_state as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id,     state,       target_org_id)
    values
      ('sr_________1', 'sb_________g',    's1_____clare', 'available', 'o_____colors');
  select throws_ok('insert_with_invalid_state', null, null, 'insert invalid recording_session state succeeded');

  prepare insert_recording_session as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id,     state,     target_org_id)
    values
      ('sr_________1', 'sb____global',    's2_____clare', 'started', 'o_____colors');
  select lives_ok('insert_recording_session');

  select results_eq(
    'select endpoint from recording_session where public_id = ''sr_________1''',
    'select endpoint from session where public_id = ''s2_____clare''');

  prepare insert_recording_session_target_address as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id,     target_org_id)
    values
      ('sr_________2', 'sb____global',    's2______cora', 'o_____colors');
  select lives_ok('insert_recording_session_target_address');

  select results_eq(
    'select endpoint from recording_session where public_id = ''sr_________2''',
    'select endpoint from session where public_id = ''s2______cora''');

  prepare insert_recording_session_plugin_host as
    insert into recording_session
      (public_id,      storage_bucket_id, session_id,     target_org_id)
    values
      ('sr_________3', 'sb____global',    's2_____carly', 'o_____colors');
  select lives_ok('insert_recording_session_plugin_host');

  -- Try to set end_time before start_time
  prepare invalid_close_recording_session as
    update recording_session set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz - '1s'::interval
    where public_id = 'sr_________1';
  select throws_ok('invalid_close_recording_session', '23514', null, 'setting end_time before start_time succeeded');

  -- Try to set state to unknown without setting error_details
  prepare update_state_to_unknown_without_error as
    update recording_session set
      state = 'unknown'
    where public_id = 'sr_________1';
  select throws_ok('update_state_to_unknown_without_error', 23514, null, 'updating the state to ''unknown'' without setting error_details succeeded');

  -- Try to set state to available while setting error details to a non-sentinel value
  prepare update_state_to_available_without_sentinel_error as
    update recording_session set
      state = 'available',
      error_details = 'an actual error'
    where public_id = 'sr_________1';
  select throws_ok('update_state_to_available_without_sentinel_error', 23514, null, 'updating the state to ''available'' without setting error_details to the sentinel value succeeded');

  -- Try to set state to unknown while setting error_details to the no error sentinel value
  prepare update_state_to_unknown_with_sentinel_error as
    update recording_session set
      state = 'unknown',
      error_details = wt_to_sentinel('no error details')
    where public_id = 'sr_________1';
  select throws_ok('update_state_to_unknown_with_sentinel_error', 23514, null, 'updating the state to ''unknown'' while setting error_details to the no error sentinel value succeeded');

  -- Try to set error_details without updating state
  prepare update_error_details_without_updating_state as
    update recording_session set
      error_details = 'some error'
    where public_id = 'sr_________1';
  select throws_ok('update_error_details_without_updating_state', 23514, null, 'setting error_details without updating the state succeeded');

  prepare update_state_to_available as
    update recording_session set
      state = 'available'
    where public_id = 'sr_________1';
  select lives_ok('update_state_to_available');

  -- Updating state again should error
  prepare update_state_to_unknown as
    update recording_session set
      state = 'unknown',
      error_details = 'some error'
    where public_id = 'sr_________1';
  select throws_ok('update_state_to_unknown', null, null, 'updating the state away from ''available'' succeeded');

  prepare update_state_to_unknown_with_error as
    update recording_session set
      state = 'unknown',
      error_details = 'some error'
    where public_id = 'sr_________2';
  select lives_ok('update_state_to_unknown_with_error');

  -- Updating state again should error
  prepare update_state_to_available_again as
    update recording_session set
      state = 'available',
      error_details = wt_to_sentinel('no error details')
    where public_id = 'sr_________2';
  select throws_ok('update_state_to_available_again', null, null, 'updating the state away from ''unknown'' succeeded');

  prepare close_recording_session as
    update recording_session set
      start_time = clock_timestamp()::timestamptz,
      end_time = clock_timestamp()::timestamptz + '1s'::interval
    where public_id = 'sr_________1';
  select lives_ok('close_recording_session');

  prepare select_session_recordings as
    select public_id::text, storage_bucket_id::text, storage_bucket_scope_id::text, session_id::text,
           user_history_public_id::text, user_history_name::text, user_history_scope_id::text, user_scope_history_type::text,
           target_history_public_id::text, target_history_name::text, target_scope_history_public_id::text,
           static_catalog_history_public_id::text, static_host_history_public_id::text,
           plugin_catalog_history_public_id::text, plugin_host_history_public_id::text, plugin_catalog_history_plugin_id::text
    from session_recording_aggregate
    where public_id in ('sr_________1', 'sr_________2', 'sr_________3')
    order by public_id;

  select results_eq(
    'select_session_recordings',
    $$VALUES
      ('sr_________1', 'sb____global', 'global', 's2_____clare',
       'u______clare', 'Clare', 'o_____colors', 'org',
       'tssh______cb', 'Blue Color SSH Target', 'p____bcolors',
       'hc__st_____b', 'h___st____b1', null, null,
        null),
        ('sr_________2', 'sb____global', 'global', 's2______cora',
       'u_______cora', 'Cora', 'o_____colors', 'org',
       'tssh______cg', 'Green Color SSH Target', 'p____gcolors',
       null, null, null, null,
        null),
       ('sr_________3', 'sb____global', 'global', 's2_____carly',
       'u______carly', 'Carly', 'o_____colors', 'org',
       'tssh______cb', 'Blue Color SSH Target', 'p____bcolors',
       null, null, 'hc__plg____b', 'h___plg___b1',
        'plg____chost')$$
         );

  -- Closing a second time should error
  select throws_ok('close_recording_session', '23602', null, 'closing a recording_session twice succeeded');

  -- Deleting the session should leave the recording in place
  delete from session where public_id = 's2_____clare';
  -- Row should still be present
  select is(count(*), 1::bigint) from recording_session where public_id = 'sr_________1';

  -- Deleting the storage bucket with active recordings should fail
  prepare delete_bucket as
    delete from storage_plugin_storage_bucket where public_id = 'sb____global';
  select throws_ok('delete_bucket', null, null, 'deleting a storage_plugin_storage_bucket with recordings succeeded');

  select * from finish();
rollback;
