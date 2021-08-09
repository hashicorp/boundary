-- source tests the whx_credential_dimension_source view.
begin;
  select plan(1);

  select is(s.*, row(
    'vl______cvl',              -- credential_library_id,
    'vault credential library', -- credential_library_type,
    'color vault library',      -- credential_library_name,
    'None',                     -- credential_library_description,
    '/secrets',                 -- credential_library_vault_path,
    'GET',                      -- credential_library_vault_http_method,
    'None',                     -- credential_library_vault_http_request_body,

    'vs_______cvs',             -- credential_store_id,
    'vault credential store',   -- credential_store_type,
    'color vault store',        -- credential_store_name,
    'None',                     -- credential_store_description,
    'blue',                     -- credential_store_vault_namespace,
    'https://vault.color',      -- credential_store_vault_address,

    't_________cb',             -- target_id,
    'tcp target',               -- target_type,
    'Blue Color Target',        -- target_name,
    'None',                     -- target_description,
    0,                          -- target_default_port_number,
    28800,                      -- target_session_max_seconds,
    1,                          -- target_session_connection_limit,

    'p____bcolors',             -- project_id,
    'Blue Color Mill',          -- project_name,
    'None',                     -- project_description,
    'o_____colors',             -- organization_id,
    'Colors R Us',              -- organization_name,
    'None'                      -- organization_description
  )::whx_credential_dimension_source)
    from whx_credential_dimension_source as s
   where s.target_id         = 't_________cb';
rollback;
