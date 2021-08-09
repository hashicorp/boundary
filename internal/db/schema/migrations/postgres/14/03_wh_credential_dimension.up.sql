begin;
  create table wh_credential_dimension (
    -- random id generated using encode(digest(gen_random_bytes(16), 'sha256'), 'base64')
    -- this is done to prevent conflicts with rows in other clusters
    -- which enables warehouse data from multiple clusters to be loaded into a
    -- single database instance
    key                                        wh_dim_id    primary key default wh_dim_id(),

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

  create unique index wh_credential_dim_current_constraint
    on wh_credential_dimension (credential_library_id, credential_store_id, target_id)
    where current_row_indicator = 'Current';

  create table wh_credential_group (
    -- random id generated using encode(digest(gen_random_bytes(16), 'sha256'), 'base64')
    -- this is done to prevent conflicts with rows in other clusters
    -- which enables warehouse data from multiple clusters to be loaded into a
    -- single database instance
    key wh_dim_id primary key default wh_dim_id()
  );

  create table wh_credential_group_membership (
    credential_group_key wh_dim_id not null,
    credential_key       wh_dim_id not null,
    credential_purpose   wh_dim_text
  );
commit;
