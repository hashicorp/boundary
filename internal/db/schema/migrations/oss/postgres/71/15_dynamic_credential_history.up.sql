-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table credential_library_history_base (
    history_id wt_url_safe_id primary key
  );
  comment on table credential_library_history_base is
    'credential_library_history_base is a base history table '
    'for credential_library history tables.';

  create function insert_credential_library_history_subtype() returns trigger
  as $$
  begin
    insert into credential_library_history_base
      (history_id)
    values
      (new.history_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_credential_library_history_subtype is
    'insert_credential_library_history_subtype is a before insert trigger '
    'function for subtypes of credential_library_history_base.';

  create function delete_credential_library_history_subtype() returns trigger
  as $$
  begin
    delete
      from credential_library_history_base
     where history_id = old.history_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_credential_library_history_subtype is
    'delete_credential_library_history_subtype() is an after delete trigger '
    'function for subtypes of credential_library_history_base.';

  -- Renamed in 99/01_credential_vault_library_refactor.up.sql
  create table credential_vault_library_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_public_id not null,
    store_id wt_public_id not null,
    vault_path text not null,
    http_method text not null
      constraint credential_vault_http_method_enm_fk
        references credential_vault_http_method_enm (name)
        on delete restrict
        on update cascade,
    http_request_body bytea,
    credential_type text not null
      constraint credential_type_enm_fk
        references credential_type_enm (name)
        on delete restrict
        on update cascade,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint credential_library_history_base_fkey
        references credential_library_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_vault_library_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_vault_library_hst is
    'credential_vault_library_hst is a history table where each row contains the values from a row '
    'in the credential_vault_library table during the time range in the valid_range column.';

  create trigger insert_credential_library_history_subtype before insert on credential_vault_library_hst
    for each row execute function insert_credential_library_history_subtype();
  create trigger delete_credential_library_history_subtype after delete on credential_vault_library_hst
    for each row execute function delete_credential_library_history_subtype();

  create trigger hst_on_insert after insert on credential_vault_library
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on credential_vault_library
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on credential_vault_library
    for each row execute function hst_on_delete();

  insert into credential_vault_library_hst
        (public_id, name, description, project_id, store_id, vault_path, http_method, http_request_body, credential_type)
  select public_id, name, description, project_id, store_id, vault_path, http_method, http_request_body, credential_type
    from credential_vault_library;

  create table credential_vault_ssh_cert_library_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_public_id not null,
    store_id wt_public_id not null,
    vault_path text not null,
    username text not null,
    key_type text not null,
    key_bits integer not null,
    ttl text,
    critical_options bytea,
    extensions bytea,
    credential_type text,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint credential_library_history_base_fkey
        references credential_library_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_vault_ssh_cert_library_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_vault_ssh_cert_library_hst is
    'credential_vault_ssh_cert_library_hst is a history table where each row contains the values from a row '
    'in the credential_vault_ssh_cert_library table during the time range in the valid_range column.';

  create trigger insert_credential_library_history_subtype before insert on credential_vault_ssh_cert_library_hst
    for each row execute function insert_credential_library_history_subtype();
  create trigger delete_credential_library_history_subtype after delete on credential_vault_ssh_cert_library_hst
    for each row execute function delete_credential_library_history_subtype();

  create trigger hst_on_insert after insert on credential_vault_ssh_cert_library
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on credential_vault_ssh_cert_library
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on credential_vault_ssh_cert_library
    for each row execute function hst_on_delete();

  insert into credential_vault_ssh_cert_library_hst
        (public_id, name, description, project_id, store_id, vault_path, username, key_type, key_bits, ttl, critical_options, extensions, credential_type)
  select public_id, name, description, project_id, store_id, vault_path, username, key_type, key_bits, ttl, critical_options, extensions, credential_type
    from credential_vault_ssh_cert_library;

  create table credential_vault_store_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_scope_id not null,
    vault_address wt_url not null,
    namespace text,
    tls_server_name text,
    tls_skip_verify boolean not null,
    worker_filter wt_bexprfilter,
    history_id wt_url_safe_id default wt_url_safe_id() primary key,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_vault_store_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_vault_store_hst is
    'credential_vault_store_hst is a history table where each row contains the values from a row '
    'in the credential_vault_store table during the time range in the valid_range column.';

  create trigger hst_on_insert after insert on credential_vault_store
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on credential_vault_store
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on credential_vault_store
    for each row execute function hst_on_delete();

  insert into credential_vault_store_hst
        (public_id, name, description, project_id, vault_address, namespace, tls_server_name, tls_skip_verify, worker_filter)
  select public_id, name, description, project_id, vault_address, namespace, tls_server_name, tls_skip_verify, worker_filter
    from credential_vault_store;

commit;
