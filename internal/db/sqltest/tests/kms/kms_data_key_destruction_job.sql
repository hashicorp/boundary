begin;
  select plan(15);
  select wtt_load('widgets', 'iam', 'kms');

  -- Should fail when inserting an unknown key_id
  prepare job_insert_unknown_key_id as
    insert into kms_data_key_version_destruction_job
      (key_id)
    values
      ('kdkv___unknown');
  select throws_ok('job_insert_unknown_key_id', '23503', null, 'insert of unknown key_id in kms_data_key_version_destruction_job succeeded');

  -- Should fail when inserting an already existing key_id
  prepare insert_already_existing_key_id as
    insert into kms_data_key_version_destruction_job
      (key_id)
    values
      ('kdkv___widget');
  select throws_ok('insert_already_existing_key_id', '23505', null, 'insert of duplicate key_id in kms_data_key_version_destruction_job succeeded');
  
  -- Should succeed when inserting new key_id
  prepare insert_new_key_id as
    insert into kms_data_key_version_destruction_job
      (key_id)
    values
      ('kdkv_______colors');
  select lives_ok('insert_new_key_id', 'insert of valid key_id in kms_data_key_version_destruction_job failed');

  -- Should fail when inserting an unknown table_name
  prepare run_insert_unknown_table_name as
    insert into kms_data_key_version_destruction_job_run
      (key_id, table_name, total_count)
    values
      ('kdkv___widget', 'unknown_table', 100);
  select throws_ok('run_insert_unknown_table_name', 'P0001', null, 'insert of unknown table_name in kms_data_key_version_destruction_job_run succeeded');

  -- Should fail when inserting a duplicate (key_id, table_name) tuple
  prepare run_insert_duplicate_key_id_table_name as
    insert into kms_data_key_version_destruction_job_run
      (key_id, table_name, total_count)
    values
      ('kdkv___widget', 'auth_token', 100);
  select throws_ok('run_insert_duplicate_key_id_table_name', '23505', null, 'insert of duplicate (key_id, table_name) tuple in kms_data_key_version_destruction_job_run succeeded');

  -- Should succeed when inserting a new, valid, (key_id, table_name) tuple
  prepare run_insert_key_id_table_name as
    insert into kms_data_key_version_destruction_job_run
      (key_id, table_name, total_count)
    values
      ('kdkv___widget', 'auth_oidc_method', 100);
  select lives_ok('run_insert_key_id_table_name', 'insert of valid (key_id, table_name) tuple in kms_data_key_version_destruction_job_run failed');

  -- Should fail when setting completed_count > total_count
  prepare run_update_invalid_completed_count as
    update kms_data_key_version_destruction_job_run set
      completed_count=101
    where
      key_id='kdkv___widget' and table_name='auth_oidc_method';
  select throws_ok('run_update_invalid_completed_count', '23514', null, 'setting completed_count > total_count in kms_data_key_version_destruction_job_run succeeded');
  
  -- Should succeed to set is_running to true
  prepare run_update_is_running as
    update kms_data_key_version_destruction_job_run set
      is_running=true
    where
      key_id='kdkv___widget' and table_name='auth_oidc_method';
  select lives_ok('run_update_is_running', 'setting is_running=true with no other run running in kms_data_key_version_destruction_job_run failed');

  -- Should fail to set is_running to true while another run is running
  prepare run_update_invalid_is_running as
    update kms_data_key_version_destruction_job_run set
      is_running=true
    where
      key_id='kdkv___widget' and table_name='auth_token';
  select throws_ok('run_update_invalid_is_running', '23505', null, 'setting is_running=true while another run is running in kms_data_key_version_destruction_job_run succeeded');

  -- Should fail to set completed_count=total_count without also setting is_running=false
  prepare run_update_completed_count_without_is_running as
    update kms_data_key_version_destruction_job_run set
      completed_count=100
    where
      key_id='kdkv___widget' and table_name='auth_oidc_method';
  select throws_ok('run_update_completed_count_without_is_running','23514', null, 'setting completed_count=total_count without also setting is_running=false in kms_data_key_version_destruction_job_run succeeded');

  -- Should succed when setting completed_count=total_count and is_running=false
  prepare run_update_completed_count_and_is_running as
    update kms_data_key_version_destruction_job_run set
      completed_count=100,
      is_running=false
    where
      key_id='kdkv___widget' and table_name='auth_oidc_method';
  select lives_ok('run_update_completed_count_and_is_running', 'setting completed_count=total_count and is_running=false kms_data_key_version_destruction_job_run failed');

  -- Should succeed to set is_running to true when no other run is running
  prepare run_update_is_running_after_other_finished as
    update kms_data_key_version_destruction_job_run set
      is_running=true
    where
      key_id='kdkv___widget' and table_name='auth_token';
  select lives_ok('run_update_is_running_after_other_finished', 'setting is_running=true while no other run is running in kms_data_key_version_destruction_job_run failed');

  -- Progress should report 'running' as one of the runs is running
  prepare list_progress as
    select key_id, scope_id, status, completed_count, total_count from kms_data_key_version_destruction_job_progress;
  select results_eq(
    'list_progress',
    $$VALUES ('kdkv___widget'::kms_private_id,'o_____widget'::kms_scope_id,'running',100::numeric,200::numeric)$$
  );

  -- Should succed when setting completed_count=total_count and is_running=false
  prepare run_update_completed_count_and_is_running_again as
    update kms_data_key_version_destruction_job_run set
      completed_count=100,
      is_running=false
    where
      key_id='kdkv___widget' and table_name='auth_token';
  select lives_ok('run_update_completed_count_and_is_running_again', 'setting completed_count=total_count and is_running=false kms_data_key_version_destruction_job_run failed');

  -- Progress should report 'completed' as all of the completed_count=total_count
  select results_eq(
    'list_progress',
    $$VALUES ('kdkv___widget'::kms_private_id,'o_____widget'::kms_scope_id,'completed',200::numeric,200::numeric)$$
  );

  select * from finish();
rollback;
