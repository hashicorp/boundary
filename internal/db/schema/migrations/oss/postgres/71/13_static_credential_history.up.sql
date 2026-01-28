-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table credential_static_history_base (
    history_id wt_url_safe_id primary key
  );
  comment on table credential_static_history_base is
    'credential_static_history_base is a base history table '
    'for credential_static history tables.';

  create function insert_credential_static_history_subtype() returns trigger
  as $$
  begin
    insert into credential_static_history_base
      (history_id)
    values
      (new.history_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_credential_static_history_subtype is
    'insert_credential_static_history_subtype is a before insert trigger '
    'function for subtypes of credential_static_history_base.';

  create function delete_credential_static_history_subtype() returns trigger
  as $$
  begin
    delete
      from credential_static_history_base
     where history_id = old.history_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_credential_static_history_subtype is
    'delete_credential_static_history_subtype() is an after delete trigger '
    'function for subtypes of credential_static_history_base.';

  create table credential_static_json_credential_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_public_id not null,
    store_id wt_public_id not null,
    object_hmac bytea not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint credential_static_history_base_fkey
        references credential_static_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_static_json_credential_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_static_json_credential_hst is
    'credential_static_json_credential_hst is a history table where each row contains the values from a row '
    'in the credential_static_json_credential table during the time range in the valid_range column.';

  create trigger insert_credential_static_history_subtype before insert on credential_static_json_credential_hst
    for each row execute function insert_credential_static_history_subtype();
  create trigger delete_credential_static_history_subtype after delete on credential_static_json_credential_hst
    for each row execute function delete_credential_static_history_subtype();

  create trigger hst_on_insert after insert on credential_static_json_credential
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on credential_static_json_credential
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on credential_static_json_credential
    for each row execute function hst_on_delete();

  insert into credential_static_json_credential_hst
        (public_id, name, description, project_id, store_id, object_hmac)
  select public_id, name, description, project_id, store_id, object_hmac
    from credential_static_json_credential;

  create table credential_static_username_password_credential_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_public_id not null,
    store_id wt_public_id not null,
    username text not null,
    password_hmac bytea not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint credential_static_history_base_fkey
        references credential_static_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_static_user_password_credential_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_static_username_password_credential_hst is
    'credential_static_username_password_credential_hst is a history table where each row contains the values from a row '
    'in the credential_static_username_password_credential table during the time range in the valid_range column.';

  create trigger insert_credential_static_history_subtype before insert on credential_static_username_password_credential_hst
    for each row execute function insert_credential_static_history_subtype();
  create trigger delete_credential_static_history_subtype after delete on credential_static_username_password_credential_hst
    for each row execute function delete_credential_static_history_subtype();

  create trigger hst_on_insert after insert on credential_static_username_password_credential
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on credential_static_username_password_credential
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on credential_static_username_password_credential
    for each row execute function hst_on_delete();

  insert into credential_static_username_password_credential_hst
        (public_id, name, description, project_id, store_id, username, password_hmac)
  select public_id, name, description, project_id, store_id, username, password_hmac
    from credential_static_username_password_credential;

  create table credential_static_ssh_private_key_credential_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_public_id not null,
    store_id wt_public_id not null,
    username text not null,
    private_key_hmac bytea not null,
    private_key_passphrase_hmac bytea,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint credential_static_history_base_fkey
        references credential_static_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_static_ssh_priv_key_credential_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_static_ssh_private_key_credential_hst is
    'credential_static_ssh_private_key_credential_hst is a history table where each row contains the values from a row '
    'in the credential_static_ssh_private_key_credential table during the time range in the valid_range column.';

  create trigger insert_credential_static_history_subtype before insert on credential_static_ssh_private_key_credential_hst
    for each row execute function insert_credential_static_history_subtype();
  create trigger delete_credential_static_history_subtype after delete on credential_static_ssh_private_key_credential_hst
    for each row execute function delete_credential_static_history_subtype();

  create trigger hst_on_insert after insert on credential_static_ssh_private_key_credential
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on credential_static_ssh_private_key_credential
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on credential_static_ssh_private_key_credential
    for each row execute function hst_on_delete();

  insert into credential_static_ssh_private_key_credential_hst
        (public_id, name, description, project_id, store_id, username, private_key_hmac, private_key_passphrase_hmac)
  select public_id, name, description, project_id, store_id, username, private_key_hmac, private_key_passphrase_hmac
    from credential_static_ssh_private_key_credential;

  create table credential_static_store_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_scope_id not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_static_store_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table credential_static_store_hst is
    'credential_static_store_hst is a history table where each row contains the values from a row '
    'in the credential_static_store table during the time range in the valid_range column.';

  create trigger hst_on_insert after insert on credential_static_store
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on credential_static_store
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on credential_static_store
    for each row execute function hst_on_delete();

  insert into credential_static_store_hst
        (public_id, name, description, project_id)
  select public_id, name, description, project_id
    from credential_static_store;

commit;
