-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(2);

  insert into wh_credential_dimension (
     credential_purpose,
     credential_library_id,       credential_library_type,            credential_library_name,     credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
     credential_library_username, credential_library_key_type_and_bits,
     credential_store_id,         credential_store_type,              credential_store_name,       credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
     target_id,                   target_type,                        target_name,                 target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
     project_id,                  project_name,                       project_description,
     organization_id,             organization_name,                  organization_description,
     current_row_indicator,       row_effective_time,                 row_expiration_time
  ) values (
     'brokered',
     'vl______wvl1',              'vault generic credential library', 'gidget vault library',      'None',                         '/secrets',                       'GET',                                '\x4e6f6e65',
     'Not Applicable',            'Not Applicable',
     'vs_______wvs',              'vault credential store',           'widget vault store',        'None',                         'default',                        'https://vault.widget',
     't_________wb',              'tcp target',                       'Big Widget Target',         'None',                         0,                                28800,                                1,
     'p____bwidget',              'Big Widget Factory',               'None',
     'o_____widget',              'Widget Inc',                       'None',
     'Current',                   current_timestamp,                  'infinity'::timestamptz
  );

  update wh_credential_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where credential_library_id = 'vl______wvl1'
         and credential_store_id   = 'vs_______wvs'
         and target_id             = 't_________wb'
         and credential_purpose    = 'brokered'
         and current_row_indicator = 'Current';

  insert into wh_credential_dimension (
     credential_purpose,
     credential_library_id,       credential_library_type,            credential_library_name,     credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
     credential_library_username, credential_library_key_type_and_bits,
     credential_store_id,         credential_store_type,              credential_store_name,       credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
     target_id,                   target_type,                        target_name,                 target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
     project_id,                  project_name,                       project_description,
     organization_id,             organization_name,                  organization_description,
     current_row_indicator,       row_effective_time,                 row_expiration_time
  ) values (
     'brokered',
     'vl______wvl1',              'vault generic credential library', 'gidget vault library',      'None',                         '/secrets',                       'GET',                                '\x4e6f6e65',
     'Not Applicable',            'Not Applicable',
     'vs_______wvs',              'vault credential store',           'widget vault store',        'None',                         'default',                        'https://vault.widget',
     't_________wb',              'tcp target',                       'Big Widget Target',         'None',                         0,                                28800,                                1,
     'p____bwidget',              'Big Widget Factory',               'None',
     'o_____widget',              'Widget Inc',                       'None',
     'Current',                   current_timestamp,                  'infinity'::timestamptz
  );

  select is(count(*), 2::bigint) from wh_credential_dimension where organization_id = 'o_____widget';
  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget' and current_row_indicator = 'Current';

  select * from finish();
rollback;
