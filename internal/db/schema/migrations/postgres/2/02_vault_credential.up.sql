begin;

  create table credential_vault_store (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fk
        references iam_scope (public_id)
        on delete cascade
        on update cascade,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    vault_address wt_url not null,
    -- the remaining text columns can be null but if they are not null, they
    -- cannot contain an empty string
    namespace text
      constraint namespace_must_not_be_empty
        check(length(trim(namespace)) > 0),
    ca_cert text -- PEM encoded certificate bundle
      constraint ca_cert_must_not_be_empty
        check(length(trim(ca_cert)) > 0),
    tls_server_name text
      constraint tls_server_name_must_not_be_empty
        check(length(trim(tls_server_name)) > 0),
    tls_skip_verify boolean not null,
    constraint credential_store_fk
      foreign key (scope_id, public_id)
      references credential_store (scope_id, public_id)
      on delete cascade
      on update cascade,
    constraint credential_vault_store_scope_id_name_uq
      unique(scope_id, name)
  );
  comment on table credential_vault_store is
    'credential_vault_store is a table where each row is a resource that represents a vault credential store. '
    'It is a credential_store subtype.';

  create trigger update_version_column after update on credential_vault_store
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_vault_store
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_vault_store
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_vault_store
    for each row execute procedure immutable_columns('public_id', 'scope_id','create_time');

  create trigger insert_credential_store_subtype before insert on credential_vault_store
    for each row execute procedure insert_credential_store_subtype();

  create trigger delete_credential_store_subtype after delete on credential_vault_store
    for each row execute procedure delete_credential_store_subtype();

  create table credential_vault_client_certificate (
    store_id wt_public_id primary key
      constraint credential_vault_store_fk
        references credential_vault_store (public_id)
        on delete cascade
        on update cascade,
    certificate text not null -- PEM encoded certificate
      constraint certificate_must_not_be_empty
        check(length(trim(certificate)) > 0),
    certificate_key text not null -- PEM encoded private key for certificate
      constraint certificate_key_must_not_be_empty
        check(length(trim(certificate_key)) > 0)
  );
  comment on table credential_vault_client_certificate is
    'credential_vault_client_certificate is a table where each row contains a client certificate that a credential_vault_store uses for mTLS when connecting to Vault. '
    'A credential_vault_store can have 0 or 1 client certificates.';

  create trigger immutable_columns before update on credential_vault_client_certificate
    for each row execute procedure immutable_columns('scope_id', 'certificate', 'certificate_key');

  create table credential_vault_library (
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint credential_vault_store_fk
        references credential_vault_store (public_id)
        on delete cascade
        on update cascade,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    vault_path text not null
      constraint vault_path_must_not_be_empty
        check(length(trim(vault_path)) > 0),
    constraint credential_vault_library_store_id_name_uq
      unique(store_id, name),
    constraint credential_library_fk
      foreign key (store_id, public_id)
      references credential_library (store_id, public_id)
      on delete cascade
      on update cascade,
    constraint credential_vault_library_store_id_public_id_uq
      unique(store_id, public_id)
  );
  comment on table credential_vault_library is
    'credential_vault_library is a table where each row is a resource that represents a vault credential library. '
    'It is a credential_library subtype and a child table of credential_vault_store.';

  create trigger update_version_column after update on credential_vault_library
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_vault_library
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_vault_library
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_vault_library
    for each row execute procedure immutable_columns('public_id', 'store_id','create_time');

  create trigger insert_credential_library_subtype before insert on credential_vault_library
    for each row execute procedure insert_credential_library_subtype();

  create trigger delete_credential_library_subtype after delete on credential_vault_library
    for each row execute procedure delete_credential_library_subtype();

  create table credential_vault_token (
    vault_token text primary key
      constraint vault_token_must_not_be_empty
        check(length(trim(vault_token)) > 0),
    store_id wt_public_id not null
      constraint credential_vault_store_fk
        references credential_vault_store (public_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    accessor text not null
      constraint credential_vault_token_accessor_uq
        unique
      constraint accessor_must_not_be_empty
        check(length(trim(accessor)) > 0),
    lease_duration bigint not null
      constraint lease_duration_must_not_be_negative
        check(lease_duration >= 0),
    last_renewal_time wt_timestamp not null
  );
  comment on table credential_vault_token is
    'credential_vault_token is a table where each row contains a Vault token for one Vault credential store.';

  create trigger update_version_column after update on credential_vault_token
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_vault_token
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_vault_token
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_vault_token
    for each row execute procedure immutable_columns('vault_token', 'store_id','create_time', 'accessor');

  create table credential_vault_lease (
    lease_id text primary key
      constraint lease_id_must_not_be_empty
        check(length(trim(lease_id)) > 0),
    library_id wt_public_id not null
      constraint credential_vault_library_fk
        references credential_vault_library (public_id)
        on delete cascade
        on update cascade,
    session_id wt_public_id not null
      constraint session_fk
        references session (public_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    lease_duration bigint not null
      constraint lease_duration_must_not_be_negative
        check(lease_duration >= 0),
    last_renewal_time wt_timestamp not null,
    is_renewable boolean not null
  );
  comment on table credential_vault_lease is
    'credential_vault_lease is a table where each row contains the lease information for a single Vault secret retrieved from a vault credential library for a session.';

  create trigger update_version_column after update on credential_vault_lease
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on credential_vault_lease
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_vault_lease
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_vault_lease
    for each row execute procedure immutable_columns('lease_id', 'library_id','session_id', 'create_time');

  create trigger insert_credential_dynamic_subtype before insert on credential_vault_lease
    for each row execute procedure insert_credential_dynamic_subtype();

  create trigger delete_credential_dynamic_subtype after delete on credential_vault_lease
    for each row execute procedure delete_credential_dynamic_subtype();

  insert into oplog_ticket (name, version)
  values
    ('credential_vault_store', 1),
    ('credential_vault_library', 1),
    ('credential_vault_lease', 1) ;

commit;
