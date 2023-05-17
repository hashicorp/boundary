-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  select plan(27);

  select has_table('recording_static_credential');

  -- tests a fk column referencing a history table
  -- add 5 to the plan for each time this function is called
  create function hst_fk_column(column_name name, pk_table name) returns text
  as $$
    select * from collect_tap(
      has_column('recording_static_credential', column_name),
      col_not_null('recording_static_credential', column_name),
      col_type_is('recording_static_credential', column_name, 'wt_url_safe_id'), -- should be the same type as the operational table
      col_hasnt_default('recording_static_credential', column_name),
      fk_ok('recording_static_credential', column_name, pk_table, 'history_id')
    );
  $$ language sql;

  select hst_fk_column('credential_static_store_hst_id', 'credential_static_store_hst');
  select hst_fk_column('credential_static_hst_id', 'credential_static_history_base');

  select has_column('recording_static_credential', 'recording_id');
  select col_not_null('recording_static_credential', 'recording_id');
  select col_type_is('recording_static_credential', 'recording_id', 'wt_public_id'); -- should be the same type as the operational table
  select col_hasnt_default('recording_static_credential', 'recording_id');
  select fk_ok('recording_static_credential', 'recording_id', 'recording_session', 'public_id');

  select has_column('recording_static_credential', 'credential_purpose');
  select col_not_null('recording_static_credential', 'credential_purpose');
  select col_type_is('recording_static_credential', 'credential_purpose', 'text'); -- should be the same type as the operational table
  select col_hasnt_default('recording_static_credential', 'credential_purpose');
  select fk_ok('recording_static_credential', 'credential_purpose', 'credential_purpose_enm', 'name');

  select col_is_pk('recording_static_credential',
    array['recording_id', 'credential_static_store_hst_id', 'credential_static_hst_id', 'credential_purpose']);
  -- 22

  prepare get_target_creds as
   select credential_static_id, credential_purpose
     from target_static_credential
    where target_id = 'tssh______cg';

  prepare get_session_creds as
   select credential_static_id, credential_purpose
     from session_credential_static
     join session on session_id = public_id
    where target_id  = 'tssh______cg'
      and session_id = 's1______cora';

  select results_eq('get_target_creds', 'get_session_creds');

  select is(count(*), 3::bigint)
    from target_static_credential
   where target_id = 'tssh______cg';

  select is(count(*), 3::bigint)
    from session_credential_static
   where session_id = 's1______cora';

  select is(count(*), 1::bigint)
    from recording_session
   where session_id = 's1______cora'
     and public_id  = 'sr1_____cora';

  select is(count(*), 3::bigint)
    from recording_static_credential
   where recording_id = 'sr1_____cora';

  select * from finish();
rollback;
