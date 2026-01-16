-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- Tests the refactor around credential_vault_library (and other associated
-- tables/views). It tests that the new structure is setup as expected with all
-- the associated triggers, FKs, constraints, etc. It does not test the refactor
-- where state is present in the database beforehand. For this, see the Go SQL
-- tests in migrations/oss/postgres_99_01_test.go.
--
-- For extra context, see migration folder 99/README.md.

begin;
  select plan(97);

  -- Redefined credential_vault_library.
  select has_table(       'credential_vault_library');
    select has_column(    'credential_vault_library', 'public_id');
      select col_is_pk(   'credential_vault_library', 'public_id');
      select col_not_null('credential_vault_library', 'public_id');

    select has_column(    'credential_vault_library', 'store_id');
      select col_not_null('credential_vault_library', 'store_id');

    select has_column(      'credential_vault_library', 'credential_type');
      select col_not_null(  'credential_vault_library', 'credential_type');
      select col_default_is('credential_vault_library', 'credential_type', 'unspecified');

    select has_column(    'credential_vault_library', 'project_id');
      select col_not_null('credential_vault_library', 'project_id');

    select has_column(    'credential_vault_library', 'create_time');
      select col_not_null('credential_vault_library', 'create_time');

    select has_column(    'credential_vault_library', 'update_time');
      select col_not_null('credential_vault_library', 'update_time');

    select fk_ok('credential_vault_library', ARRAY['public_id',  'store_id', 'credential_type', 'project_id'], 'credential_library',       ARRAY['public_id',  'store_id', 'credential_type', 'project_id']);
    select fk_ok('credential_vault_library', ARRAY['project_id', 'store_id'],                                  'credential_vault_store',   ARRAY['project_id', 'public_id']);

    select has_trigger('credential_vault_library', 'immutable_columns');
    select has_trigger('credential_vault_library', 'insert_credential_library_subtype');
    select has_trigger('credential_vault_library', 'delete_credential_library_subtype');
    select has_trigger('credential_vault_library', 'update_credential_library_table_update_time');

  -- Vault generic credential library table.
  select has_table('credential_vault_generic_library');
    select has_column( 'credential_vault_generic_library', 'public_id');
      select col_is_pk('credential_vault_generic_library', 'public_id');
    select has_column( 'credential_vault_generic_library', 'store_id');
    select has_column( 'credential_vault_generic_library', 'name');
    select has_column( 'credential_vault_generic_library', 'description');
    select has_column( 'credential_vault_generic_library', 'create_time');
    select has_column( 'credential_vault_generic_library', 'update_time');
    select has_column( 'credential_vault_generic_library', 'version');
    select has_column( 'credential_vault_generic_library', 'vault_path');
    select has_column( 'credential_vault_generic_library', 'http_method');
    select has_column( 'credential_vault_generic_library', 'http_request_body');
    select has_column( 'credential_vault_generic_library', 'credential_type');
    select has_column( 'credential_vault_generic_library', 'project_id');

    select fk_ok('credential_vault_generic_library', ARRAY['project_id', 'store_id', 'public_id', 'credential_type'], 'credential_vault_library', ARRAY['project_id', 'store_id', 'public_id', 'credential_type']);

    select has_trigger('credential_vault_generic_library', 'immutable_columns');
    select has_trigger('credential_vault_generic_library', 'insert_deleted_id');
    select has_trigger('credential_vault_generic_library', 'insert_credential_vault_library_subtype');
    select has_trigger('credential_vault_generic_library', 'update_credential_vault_library_table_update_time');
    select has_trigger('credential_vault_generic_library', 'delete_credential_vault_library_subtype');
    select has_trigger('credential_vault_generic_library', 'before_insert_credential_vault_library');
    select has_trigger('credential_vault_generic_library', 'hst_on_insert');
    select has_trigger('credential_vault_generic_library', 'hst_on_update');
    select has_trigger('credential_vault_generic_library', 'hst_on_delete');

  -- Vault generic deleted table.
  select hasnt_table('credential_vault_library_deleted');
  select has_table(  'credential_vault_generic_library_deleted');

  -- Vault generic history table.
  select hasnt_table('credential_vault_library_hst');
  select has_table(  'credential_vault_generic_library_hst');

  -- Mapping overrides: Base table, UP, UPD and SSH PK.
  select hasnt_table('credential_vault_library_mapping_override');
  select has_table('credential_vault_generic_library_mapping_override');

  select hasnt_table('credential_vault_library_username_password_mapping_override');
  select has_table('credential_vault_generic_library_username_password_mapping_ovrd');

  select hasnt_table('credential_vault_library_username_password_domain_mapping_ovrd');
  select has_table('credential_vault_generic_library_usern_pass_domain_mapping_ovrd');

  select hasnt_table('credential_vault_library_ssh_private_key_mapping_override');
  select has_table('credential_vault_generic_library_ssh_private_key_mapping_ovrd');

  -- Views.
  select has_view('credential_vault_library_issue_credentials');
  select has_view('whx_credential_dimension_source');

  select hasnt_view('credential_vault_generic_hst_aggregate');
  select has_view('credential_vault_generic_library_hst_aggregate');

  select hasnt_view('credential_vault_library_list_lookup');
  select has_view('credential_vault_generic_library_list_lookup');

  -- Vault dynamic credentials table.
  select fk_ok('credential_vault_credential', 'library_id', 'credential_vault_library', 'public_id');

  -- We can be reasonably sure the structure is as intended. Now we insert data
  -- to actually test it.
  select lives_ok(
    $$
      insert into iam_scope
        (parent_id, type,  public_id,      name)
      values
        ('global',  'org', 'o_LaIu234Pg6', 'Test Org Scope');

      insert into iam_scope
        (parent_id,       type,      public_id,      name)
      values
        ('o_LaIu234Pg6',  'project', 'p_31ouN5ldA2', 'Test Project Scope');

      insert into credential_vault_store
        (public_id,        project_id,     name,                          vault_address)
      values
        ('csvlt_5n3A2kJo', 'p_31ouN5ldA2', 'Test Vault Credential Store', 'https://my.vault.instance.local');

      insert into credential_vault_generic_library
        (public_id,        store_id,         project_id,     name,             description,                             vault_path,       http_method, http_request_body)
      values
        ('clvlt_V134iOjA', 'csvlt_5n3A2kJo', 'p_31ouN5ldA2', 'vault_generic1', 'Test vault generic credential library', '/my/vault/path', 'POST',      'my_http_request_body');

      insert into credential_vault_generic_library
        (public_id,        store_id,         project_id,     credential_type,     name,             description,                               vault_path,        http_method)
      values
        ('clvlt_j5oK17vG', 'csvlt_5n3A2kJo', 'p_31ouN5ldA2', 'username_password', 'vault_generic2', 'Test vault generic credential library 2', '/my/vault2/path', 'GET');

      insert into credential_vault_ssh_cert_library
        (public_id,          store_id,         project_id,     name,              vault_path,          username, key_type,  key_bits)
      values
        ('clvsclt_35iWGH12', 'csvlt_5n3A2kJo', 'p_31ouN5ldA2', 'vault_ssh_cert1', '/ssh/issue/mycert', 'myuser', 'ed25519', 0);

      insert into credential_vault_generic_library_usern_pass_domain_mapping_ovrd
           values ('clvlt_V134iOjA', 'custom_username_attr', 'custom_pw_attr', 'custom_domain_attr');

      insert into credential_vault_generic_library_username_password_mapping_ovrd
           values ('clvlt_j5oK17vG', 'custom_username_attr', 'custom_pw_attr');
    $$
  );

  -- Assert the data was inserted correctly into the subtype tables.
  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             name,
             description,
             version,
             vault_path,
             http_method,
             http_request_body,
             credential_type,
             project_id
        from credential_vault_generic_library
       where public_id = 'clvlt_V134iOjA';
    $$,
    row( -- Expect:
      'clvlt_V134iOjA'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'vault_generic1'::wt_name,
      'Test vault generic credential library'::wt_description,
      1::wt_version,
      '/my/vault/path'::text,
      'POST'::text,
      'my_http_request_body'::bytea,
      'unspecified'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );

  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             name,
             description,
             version,
             vault_path,
             http_method,
             http_request_body,
             credential_type,
             project_id
        from credential_vault_generic_library
       where public_id = 'clvlt_j5oK17vG';
    $$,
    row( -- Expect:
      'clvlt_j5oK17vG'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'vault_generic2'::wt_name,
      'Test vault generic credential library 2'::wt_description,
      1::wt_version,
      '/my/vault2/path'::text,
      'GET'::text,
      null::bytea,
      'username_password'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );

  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             name,
             version,
             vault_path,
             username,
             key_type,
             key_bits,
             ttl,
             key_id,
             critical_options,
             extensions,
             credential_type,
             project_id,
             additional_valid_principals
        from credential_vault_ssh_cert_library
       where public_id = 'clvsclt_35iWGH12';
    $$,
    row( -- Expect:
      'clvsclt_35iWGH12'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'vault_ssh_cert1'::wt_name,
      1::wt_version,
      '/ssh/issue/mycert'::text,
      'myuser'::text,
      'ed25519'::text,
      0::integer,
      null::text,
      null::text,
      null::bytea,
      null::bytea,
      'ssh_certificate'::text,
      'p_31ouN5ldA2'::wt_public_id,
      null::text
    )
  );

  -- Assert that the data was inserted correctly into the base tables
  -- (credential_vault_library and credential_library).
  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             credential_type,
             project_id
        from credential_vault_library
       where public_id = 'clvlt_V134iOjA';
    $$,
    row( -- Expect:
      'clvlt_V134iOjA'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'unspecified'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );
  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             credential_type,
             project_id
        from credential_library
       where public_id = 'clvlt_V134iOjA';
    $$,
    row( -- Expect:
      'clvlt_V134iOjA'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'unspecified'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );

  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             credential_type,
             project_id
        from credential_vault_library
       where public_id = 'clvlt_j5oK17vG';
    $$,
    row( -- Expect:
      'clvlt_j5oK17vG'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'username_password'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );
  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             credential_type,
             project_id
        from credential_library
       where public_id = 'clvlt_j5oK17vG';
    $$,
    row( -- Expect:
      'clvlt_j5oK17vG'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'username_password'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );

  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             credential_type,
             project_id
        from credential_vault_library
       where public_id = 'clvsclt_35iWGH12';
    $$,
    row( -- Expect:
      'clvsclt_35iWGH12'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'ssh_certificate'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );
  select row_eq(
    $$ -- Query:
      select public_id,
             store_id,
             credential_type,
             project_id
        from credential_library
       where public_id = 'clvsclt_35iWGH12';
    $$,
    row( -- Expect:
      'clvsclt_35iWGH12'::wt_public_id,
      'csvlt_5n3A2kJo'::wt_public_id,
      'ssh_certificate'::text,
      'p_31ouN5ldA2'::wt_public_id
    )
  );

  -- Assert that the data was inserted correctly into the history tables.
  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_hst
       where public_id = 'clvlt_V134iOjA';
    $$,
    row(1::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_library_history_base as base
        join credential_vault_generic_library_hst as vglh on base.history_id = vglh.history_id
       where vglh.public_id = 'clvlt_V134iOjA';
    $$,
    row(1::bigint)
  );

  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_hst
       where public_id = 'clvlt_j5oK17vG';
    $$,
    row(1::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_library_history_base as base
        join credential_vault_generic_library_hst as vglh on base.history_id = vglh.history_id
       where vglh.public_id = 'clvlt_j5oK17vG';
    $$,
    row(1::bigint)
  );

  select row_eq(
    $$
      select count(*)
        from credential_vault_ssh_cert_library_hst
       where public_id = 'clvsclt_35iWGH12';
    $$,
    row(1::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_library_history_base as base
        join credential_vault_ssh_cert_library_hst as vsclh on base.history_id = vsclh.history_id
       where vsclh.public_id = 'clvsclt_35iWGH12';
    $$,
    row(1::bigint)
  );

  -- Assert that the data was inserted correctly into the mapping override
  -- tables.
  select row_eq(
    $$
        select count(*)
          from credential_vault_generic_library_mapping_override;
    $$,
    row(2::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_usern_pass_domain_mapping_ovrd
       where library_id = 'clvlt_V134iOjA';
    $$,
    row(1::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_username_password_mapping_ovrd
       where library_id = 'clvlt_j5oK17vG';
    $$,
    row(1::bigint)
  );

  -- Update credential library. Verify that:
  --   - The update works.
  --   - Version column is incremented.
  --   - A new history entry is created both in the base table and subtype table.
  select lives_ok(
    $$
      update credential_vault_generic_library
        set
          name         = 'vault_generic1_updated',
          vault_path   = '/my/updated/vault/path'
       where public_id = 'clvlt_V134iOjA';
    $$
  );

  select row_eq(
    $$ -- Query:
      select public_id,
             name,
             version,
             vault_path
        from credential_vault_generic_library
       where public_id = 'clvlt_V134iOjA';
    $$,
    row( -- Expect:
      'clvlt_V134iOjA'::wt_public_id,
      'vault_generic1_updated'::wt_name,
      2::wt_version,
      '/my/updated/vault/path'::text
    )
  );

  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_hst
       where public_id = 'clvlt_V134iOjA';
    $$,
    row(2::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_library_history_base as base
        join credential_vault_generic_library_hst as vglh on base.history_id = vglh.history_id
       where vglh.public_id = 'clvlt_V134iOjA';
    $$,
    row(2::bigint)
  );

  -- Delete credential library. Verify that:
  --   - The delete works.
  --   - The deleted credential library id is inserted into the deleted table.
  --   - The deleted credential library row is deleted from the base tables.
  --   - Mapping overrides that reference this credential library are
  --     automatically deleted.
  select lives_ok(
    $$
      delete from credential_vault_generic_library
            where public_id = 'clvlt_j5oK17vG';
    $$
  );

  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_deleted
       where public_id = 'clvlt_j5oK17vG';
    $$,
    row(1::bigint)
  );

  select row_eq(
    $$
      select count(*)
        from credential_vault_library
       where public_id = 'clvlt_j5oK17vG';
    $$,
    row(0::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_library
       where public_id = 'clvlt_j5oK17vG';
    $$,
    row(0::bigint)
  );

  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_username_password_mapping_ovrd
       where library_id = 'clvlt_j5oK17vG';
    $$,
    row(0::bigint)
  );
  select row_eq(
    $$
      select count(*)
        from credential_vault_generic_library_mapping_override
       where library_id = 'clvlt_j5oK17vG';
    $$,
    row(0::bigint)
  );

  -- Check data in views.
  select results_eq(
    $$
        select credential_library_id,
               credential_library_name
          from whx_credential_dimension_source
      order by credential_library_name;
    $$,
    $$
      values
        ('cvl_______g1'::wt_public_id,     'green vault library'),
        ('cvl__ssh__g1'::wt_public_id, 'green vault ssh library')
    $$
  );

  select results_eq(
    $$
        select public_id,
               name
          from credential_vault_library_issue_credentials
      order by name;
    $$,
    $$
      values
        (    'cvl__ldap_b1'::wt_public_id,  'blue vault ldap library'::wt_name),
        (    'cvl_______b1'::wt_public_id,       'blue vault library'::wt_name),
        (    'cvl__ssh__b1'::wt_public_id,   'blue vault ssh library'::wt_name),
        (    'cvl__ldap_g1'::wt_public_id, 'green vault ldap library'::wt_name),
        (    'cvl_______g1'::wt_public_id,      'green vault library'::wt_name),
        (    'cvl__ssh__g1'::wt_public_id,  'green vault ssh library'::wt_name),
        (    'cvl__ldap_r1'::wt_public_id,   'red vault ldap library'::wt_name),
        (    'cvl_______r1'::wt_public_id,        'red vault library'::wt_name),
        (    'cvl__ssh__r1'::wt_public_id,    'red vault ssh library'::wt_name),
        (  'clvlt_V134iOjA'::wt_public_id,   'vault_generic1_updated'::wt_name),
        ('clvsclt_35iWGH12'::wt_public_id,          'vault_ssh_cert1'::wt_name);
    $$
  );

  select results_eq(
    $$
        select public_id,
               name
          from credential_vault_generic_library_list_lookup
      order by name;
    $$,
    $$
      values
        (    'cvl_______b1'::wt_public_id,     'blue vault library'::wt_name),
        (    'cvl_______g1'::wt_public_id,    'green vault library'::wt_name),
        (    'cvl_______r1'::wt_public_id,      'red vault library'::wt_name),
        (  'clvlt_V134iOjA'::wt_public_id, 'vault_generic1_updated'::wt_name);
    $$
  );

  select results_eq(
    $$
        select public_id,
               name
          from credential_vault_generic_library_hst_aggregate
      order by name;
    $$,
    $$
      values
        ('cvl_______g1'::wt_public_id, 'green vault library'::wt_name)
    $$
  );

  select * from finish();
rollback;
