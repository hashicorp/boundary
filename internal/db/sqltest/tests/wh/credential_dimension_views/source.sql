-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- source tests the whx_credential_dimension_source view.
begin;
  select plan(1);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');
  insert into session
    ( project_id,      target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____bwidget',  't_________wb', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's1____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s1____walter', 's___1wb-sths', 'h_____wb__01');
  insert into session_credential_dynamic
    ( session_id,    library_id,     credential_id,  credential_purpose)
  values
    ('s1____walter', 'vl______wvl1', null,           'brokered');

  select is(s.*, row(
    's1____walter',
    'brokered',                         -- credential_purpose,
    'vl______wvl1',                     -- credential_library_id,
    'vault generic credential library', -- credential_library_type,
    'widget vault library',             -- credential_library_name,
    'None',                             -- credential_library_description,
    '/secrets',                         -- credential_library_vault_path,
    'GET',                              -- credential_library_vault_http_method,
    'Not Applicable',                   -- credential_library_vault_http_request_body,

    'Not Applicable',                   -- credential_library_username,
    'Not Applicable',                   -- credential_library_key_type_and_bits,

    'vs_______wvs',                     -- credential_store_id,
    'vault credential store',           -- credential_store_type,
    'widget vault store',               -- credential_store_name,
    'None',                             -- credential_store_description,
    'default',                          -- credential_store_vault_namespace,
    'https://vault.widget',             -- credential_store_vault_address,

    't_________wb',                     -- target_id,
    'tcp target',                       -- target_type,
    'Big Widget Target',                -- target_name,
    'None',                             -- target_description,
    0,                                  -- target_default_port_number,
    28800,                              -- target_session_max_seconds,
    -1,                                 -- target_session_connection_limit,

    'p____bwidget',                     -- project_id,
    'Big Widget Factory',               -- project_name,
    'None',                             -- project_description,
    'o_____widget',                     -- organization_id,
    'Widget Inc',                       -- organization_name,
    'None'                              -- organization_description
  )::whx_credential_dimension_source)
    from whx_credential_dimension_source as s
   where s.target_id         = 't_________wb';

rollback;
