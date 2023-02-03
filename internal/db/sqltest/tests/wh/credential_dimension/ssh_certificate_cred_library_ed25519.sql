-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- ssh_certificate_cred_library tests the wh_credential_dimension when
-- sessions are created with targets that use a vault ssh cert credential library
begin;
  select plan(3);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- ensure no existing dimensions
  select is(count(*), 0::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  -- insert first session, should result in a new credentials dimension
  insert into session
    ( project_id,      target_id,      user_id,        auth_token_id,  certificate,  endpoint, public_id)
  values
    ('p____swidget',  't________ws3', 'u_____walter', 'tok___walter', 'abc'::bytea, 'ep1',    's3____walter');
  insert into session_host_set_host
    (session_id, host_set_id, host_id)
  values
    ('s3____walter', 's___1ws-sths', 'h_____ws__01');
  insert into session_credential_dynamic
    ( session_id,     library_id,     credential_id,  credential_purpose)
  values
    ('s3____walter',  'vscl____wvl3', null,           'injected_application');
  select is(count(*), 1::bigint) from wh_credential_dimension where organization_id = 'o_____widget';

  prepare select_credential_dimensions as
    select
      credential_purpose::text,
      credential_library_id::text,       credential_library_type::text,              credential_library_name::text,  credential_library_description::text, credential_library_vault_path::text,    credential_library_vault_http_method::text, credential_library_vault_http_request_body::text,
      credential_library_username::text, credential_library_key_type_and_bits::text,
      credential_store_id::text,         credential_store_type::text,                credential_store_name::text,    credential_store_description::text,   credential_store_vault_namespace::text, credential_store_vault_address::text,
      target_id::text,                   target_type::text,                          target_name::text,              target_description::text,             target_default_port_number,             target_session_max_seconds,                 target_session_connection_limit,
      project_id::text,                  project_name::text,                         project_description::text,
      organization_id::text,             organization_name::text,                    organization_description::text,
      current_row_indicator::text
     from wh_credential_dimension
    where organization_id = 'o_____widget';

  select results_eq(
    'select_credential_dimensions',
    $$VALUES
    (
      'injected_application',
      'vscl____wvl3',                    'vault ssh certificate credential library', 'widget ssh ed25519',           'None',                               '/ssh/sign/user',                       'Not Applicable',                           'Not Applicable',
      'user',                            'ed25519',
      'vs______swvs',                    'vault credential store',                   'small widget vault store',     'None',                               'default',                              'https://small.vault.widget',
      't________ws3',                    'tcp target',                               'Small Widget Target 3',        'None',                               0,                                      28800,                                      -1,
      'p____swidget',                    'Small Widget Factory',                     'None',
      'o_____widget',                    'Widget Inc',                               'None',
      'Current'
    )$$
  );

  select * from finish();
rollback;

