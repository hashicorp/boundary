-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(31);

  select has_table('recording_dynamic_credential');
  select has_view('credential_vault_generic_library_hst_aggregate', 'view for aggregate vault generic library history info does not exist');
  select has_view('credential_vault_ssh_cert_library_hst_aggregate', 'view for aggregate vault ssh cert library history info does not exist');

  -- tests a fk column referencing a history table
  -- add 5 to the plan for each time this function is called
  create function hst_fk_column(column_name name, pk_table name) returns text
  as $$
    select * from collect_tap(
      has_column('recording_dynamic_credential', column_name),
      col_not_null('recording_dynamic_credential', column_name),
      col_type_is('recording_dynamic_credential', column_name, 'wt_url_safe_id'), -- should be the same type as the operational table
      col_hasnt_default('recording_dynamic_credential', column_name),
      fk_ok('recording_dynamic_credential', column_name, pk_table, 'history_id')
    );
  $$ language sql;

  select hst_fk_column('credential_vault_store_hst_id', 'credential_vault_store_hst');
  select hst_fk_column('credential_library_hst_id', 'credential_library_history_base');

  select has_column('recording_dynamic_credential', 'recording_id');
  select col_not_null('recording_dynamic_credential', 'recording_id');
  select col_type_is('recording_dynamic_credential', 'recording_id', 'wt_public_id'); -- should be the same type as the operational table
  select col_hasnt_default('recording_dynamic_credential', 'recording_id');
  select fk_ok('recording_dynamic_credential', 'recording_id', 'recording_session', 'public_id');

  select has_column('recording_dynamic_credential', 'credential_purpose');
  select col_not_null('recording_dynamic_credential', 'credential_purpose');
  select col_type_is('recording_dynamic_credential', 'credential_purpose', 'text'); -- should be the same type as the operational table
  select col_hasnt_default('recording_dynamic_credential', 'credential_purpose');
  select fk_ok('recording_dynamic_credential', 'credential_purpose', 'credential_purpose_enm', 'name');

  select col_is_pk('recording_dynamic_credential',
    array['recording_id', 'credential_vault_store_hst_id', 'credential_library_hst_id', 'credential_purpose']);

  prepare get_target_creds as
   select credential_library_id, credential_purpose
     from target_credential_library
    where target_id = 'tssh______cg';

  prepare get_session_creds as
   select library_id, credential_purpose
     from session_credential_dynamic
     join session on session_id = public_id
    where target_id  = 'tssh______cg'
      and session_id = 's1______cora';

  select results_eq('get_target_creds', 'get_session_creds');

  prepare select_recording_vault_libraries as
    select recording_id::text, public_id::text, store_public_id::text, purposes::text
    from credential_vault_generic_library_hst_aggregate
    where recording_id = 'sr1_____cora'
    order by public_id;

  select results_eq(
     'select_recording_vault_libraries',
         $$VALUES
    ('sr1_____cora', 'cvl_______g1', 'cvs__gcolors', 'brokered')$$
       );

  prepare select_recording_vault_ssh_cert_libraries as
    select recording_id::text, public_id::text, store_public_id::text, purposes::text
    from credential_vault_ssh_cert_library_hst_aggregate
    where recording_id = 'sr1_____cora'
    order by public_id;

  select results_eq(
     'select_recording_vault_ssh_cert_libraries',
       $$VALUES
    ('sr1_____cora', 'cvl__ssh__g1', 'cvs__gcolors', 'injected_application')$$
     );

  select is(count(*), 2::bigint)
    from target_credential_library
   where target_id = 'tssh______cg';

  select is(count(*), 2::bigint)
    from session_credential_dynamic
   where session_id = 's1______cora';

  select is(count(*), 1::bigint)
    from recording_session
   where session_id = 's1______cora'
     and public_id  = 'sr1_____cora';

  select is(count(*), 2::bigint)
    from recording_dynamic_credential
   where recording_id = 'sr1_____cora';

  select * from finish();
rollback;
