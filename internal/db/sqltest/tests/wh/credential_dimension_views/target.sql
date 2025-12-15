-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- target tests teh whx_credential_dimension_target view.
begin;
  select plan(2);

  select is_empty($$select * from whx_credential_dimension_target where target_id = 't_________wb'$$);

  insert into wh_credential_dimension
    (
      key,
      credential_purpose,
      credential_library_id,       credential_library_type,            credential_library_name,     credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
      credential_library_username, credential_library_key_type_and_bits,
      credential_store_id,         credential_store_type,              credential_store_name,       credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
      target_id,                   target_type,                        target_name,                 target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
      project_id,                  project_name,                       project_description,
      organization_id,             organization_name,                  organization_description,
      current_row_indicator,       row_effective_time,                 row_expiration_time
    )
  values
    (
      'wcd________1',
      'brokered',
      'vl_______wvl',              'vault generic credential library', 'widget vault library',      'None',                         '/secrets',                       'GET',                                'None',
      'Not Applicable',            'Not Applicable',
      'vs_______wvs',              'vault credential store',           'widget vault store',        'None',                         'blue',                           'https://vault.widget',
      't_________wb',              'tcp target',                       'Big Widget Target',         'None',                         0,                                28800,                                1,
      'p____bwidget',              'Big Widget Factory',               'None',
      'o_____widget',              'Widget Inc',                       'None',
      'Current',                   '2021-07-21T12:01'::timestamptz,    'infinity'::timestamptz
    );

  select is(t.*, row(
    'wcd________1',
    'brokered',
    'vl_______wvl',    'vault generic credential library', 'widget vault library', 'None',           '/secrets',       'GET',                  'None',
     'Not Applicable', 'Not Applicable',
    'vs_______wvs',    'vault credential store',           'widget vault store',   'None',           'blue',           'https://vault.widget',
    't_________wb',    'tcp target',                       'Big Widget Target',    'None',           0,                28800,                  1,
    'p____bwidget',    'Big Widget Factory',               'None',
    'o_____widget',    'Widget Inc',                       'None'
  )::whx_credential_dimension_target)
    from whx_credential_dimension_target as t
   where t.target_id         = 't_________wb';

  select * from finish();
rollback;

