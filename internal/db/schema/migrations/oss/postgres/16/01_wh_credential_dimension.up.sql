-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- replaces check from internal/db/schema/migrations/postgres/0/60_wh_domain_types.up.sql
  alter domain wh_public_id drop constraint wh_public_id_check;
  alter domain wh_public_id add constraint wh_public_id_check
  check(
    value = 'None'
    or
    value = 'Unknown'
    or
    length(trim(value)) > 10
  );

  create table wh_credential_dimension (
    -- random id generated using encode(digest(gen_random_bytes(16), 'sha256'), 'base64')
    -- this is done to prevent conflicts with rows in other clusters
    -- which enables warehouse data from multiple clusters to be loaded into a
    -- single database instance
    key                                        wh_dim_key    primary key default wh_dim_key(),

    credential_purpose                         wh_dim_text,
    credential_library_id                      wh_public_id not null,
    credential_library_type                    wh_dim_text,
    credential_library_name                    wh_dim_text,
    credential_library_description             wh_dim_text,
    credential_library_vault_path              wh_dim_text,
    credential_library_vault_http_method       wh_dim_text,
    credential_library_vault_http_request_body wh_dim_text,

    credential_store_id                        wh_public_id not null,
    credential_store_type                      wh_dim_text,
    credential_store_name                      wh_dim_text,
    credential_store_description               wh_dim_text,
    credential_store_vault_namespace           wh_dim_text,
    credential_store_vault_address             wh_dim_text,

    target_id                                  wh_public_id not null,
    target_type                                wh_dim_text,
    target_name                                wh_dim_text,
    target_description                         wh_dim_text,
    target_default_port_number                 integer      not null,
    target_session_max_seconds                 integer      not null,
    target_session_connection_limit            integer      not null,

    project_id                                 wt_scope_id  not null,
    project_name                               wh_dim_text,
    project_description                        wh_dim_text,

    organization_id                            wt_scope_id  not null,
    organization_name                          wh_dim_text,
    organization_description                   wh_dim_text,

    current_row_indicator                      wh_dim_text,
    row_effective_time                         wh_timestamp,
    row_expiration_time                        wh_timestamp
  );

  -- https://www.postgresql.org/docs/current/indexes-partial.html
  create unique index wh_credential_dim_current_constraint
    on wh_credential_dimension (credential_library_id, credential_store_id, target_id, credential_purpose)
    where current_row_indicator = 'Current';

  -- One part of a bridge table to associated the set of wh_credential_dimension with a fact table.
  -- The other part of the bridge is wh_credential_group_membership.
  create table wh_credential_group (
    -- random id generated using encode(digest(gen_random_bytes(16), 'sha256'), 'base64')
    -- this is done to prevent conflicts with rows in other clusters
    -- which enables warehouse data from multiple clusters to be loaded into a
    -- single database instance
    key wh_dim_key primary key default wh_dim_key()
  );

  -- The second part of the bridge table. The other part is wh_credential_group.
  create table wh_credential_group_membership (
    credential_group_key wh_dim_key not null
      references wh_credential_group (key)
      on delete restrict
      on update cascade,
    credential_key       wh_dim_key not null
      references wh_credential_dimension (key)
      on delete restrict
      on update cascade
  );

  -- Add "no credentials" and "Unknown" group an dimension.
  -- When a session has no credentials "no credentials" is used as the "None" value.
  -- "Unknown" is used for existing data prior to the credential_dimension existing.
  insert into wh_credential_group
    (key)
  values
    ('no credentials'),
    ('Unknown');
  insert into wh_credential_dimension (
    key,
    credential_purpose,
    credential_library_id, credential_library_type, credential_library_name,  credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
    credential_store_id,   credential_store_type,   credential_store_name,    credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
    target_id,             target_type,             target_name,              target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
    project_id,            project_name,            project_description,
    organization_id,       organization_name,       organization_description,
    current_row_indicator, row_effective_time,      row_expiration_time
  )
  values
  (
    'no credential',
    'None',
    'None',                'None',                  'None',                   'None',                         'None',                           'None',                               'None',
    'None',                'None',                  'None',                   'None',                         'None',                           'None',
    'None',                'None',                  'None',                   'None',                         -1,                               -1,                                   -1,
    '00000000000',         'None',                  'None',
    '00000000000',         'None',                  'None',
    'Current',             now(),                   'infinity'::timestamptz
  ),
  (
    'Unknown',
    'Unknown',
    'Unknown',             'Unknown',               'Unknown',                'Unknown',                      'Unknown',                        'Unknown',                            'Unknown',
    'Unknown',             'Unknown',               'Unknown',                'Unknown',                      'Unknown',                        'Unknown',
    'Unknown',             'Unknown',               'Unknown',                'Unknown',                      -1,                               -1,                                   -1,
    '00000000000',         'Unknown',               'Unknown',
    '00000000000',         'Unknown',               'Unknown',
    'Current',             now(),                   'infinity'::timestamptz
  );
  insert into wh_credential_group_membership
    (credential_group_key, credential_key)
  values
    ('no credentials',     'no credential'),
    ('Unknown',            'Unknown');

commit;
