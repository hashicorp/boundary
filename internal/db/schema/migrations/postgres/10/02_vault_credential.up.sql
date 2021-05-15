begin;

  create table credential_vault_store (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
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
    ca_cert bytea -- PEM encoded certificate bundle
      constraint ca_cert_must_not_be_empty
        check(length(ca_cert) > 0),
    tls_server_name text
      constraint tls_server_name_must_not_be_empty
        check(length(trim(tls_server_name)) > 0),
    tls_skip_verify boolean default false not null,
    constraint credential_store_fkey
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

  create table credential_vault_token_status_enm (
    name text primary key
      constraint only_predefined_token_statuses_allowed
      check (
        name in (
          'current',
          'maintaining',
          'revoked',
          'expired'
        )
      )
  );
  comment on table credential_vault_token_status_enm is
    'credential_vault_token_status_enm is an enumeration table for the status of vault tokens. '
    'It contains rows for representing the current, maintaining, revoked, and expired statuses.';

  insert into credential_vault_token_status_enm (name)
  values
    ('current'),
    ('maintaining'),
    ('revoked'),
    ('expired');

  create table credential_vault_token (
    token_hmac bytea primary key, -- hmac-sha256(token, key(blake2b-256(token_accessor))
    token bytea not null, -- encrypted value
    store_id wt_public_id not null
      constraint credential_vault_store_fkey
        references credential_vault_store (public_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    last_renewal_time timestamp with time zone not null,
    expiration_time timestamp with time zone not null
      constraint last_renewal_time_must_be_before_expiration_time
        check(last_renewal_time < expiration_time),
    key_id text not null
      constraint kms_database_key_version_fkey
        references kms_database_key_version (private_id)
        on delete restrict
        on update cascade,
    status text not null
      constraint credential_vault_token_status_enm_fkey
        references credential_vault_token_status_enm (name)
        on delete restrict
        on update cascade
  );
  comment on table credential_vault_token is
    'credential_vault_token is a table where each row contains a Vault token for one Vault credential store. '
    'A credential store can have only one vault token with the status of current';
  comment on column credential_vault_token.token_hmac is
    'token_hmac contains the hmac-sha256 value of the token. '
    'The hmac key is the blake2b-256 value of the token accessor.';

  -- https://www.postgresql.org/docs/current/indexes-partial.html
  create unique index credential_vault_token_current_status_constraint
    on credential_vault_token (store_id)
    where status = 'current';

  create trigger update_time_column before update on credential_vault_token
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on credential_vault_token
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on credential_vault_token
    for each row execute procedure immutable_columns('token_hmac', 'token', 'store_id','create_time');

  -- insert_credential_vault_token() is a before insert trigger
  -- function for credential_vault_token that changes the status of the current
  -- token to 'maintaining'
  create or replace function insert_credential_vault_token()
    returns trigger
  as $$
  begin
    update credential_vault_token
       set status   = 'maintaining'
     where store_id = new.store_id
       and status   = 'current';
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_credential_vault_token before insert on credential_vault_token
    for each row execute procedure insert_credential_vault_token();

  create table credential_vault_client_certificate (
    store_id wt_public_id primary key
      constraint credential_vault_store_fkey
        references credential_vault_store (public_id)
        on delete cascade
        on update cascade,
    certificate bytea not null -- PEM encoded certificate
      constraint certificate_must_not_be_empty
        check(length(certificate) > 0),
    certificate_key bytea not null -- encrypted PEM encoded private key for certificate
      constraint certificate_key_must_not_be_empty
        check(length(certificate_key) > 0),
    key_id text not null
      constraint kms_database_key_version_fkey
        references kms_database_key_version (private_id)
        on delete restrict
        on update cascade
  );
  comment on table credential_vault_client_certificate is
    'credential_vault_client_certificate is a table where each row contains a client certificate that a credential_vault_store uses for mTLS when connecting to Vault. '
    'A credential_vault_store can have 0 or 1 client certificates.';

  create trigger immutable_columns before update on credential_vault_client_certificate
    for each row execute procedure immutable_columns('store_id');

  create table credential_vault_http_method_enm (
    name text primary key
      constraint only_predefined_http_methods_allowed
      check (
        name in (
          'GET',
          'POST'
        )
      )
  );
  comment on table credential_vault_http_method_enm is
    'credential_vault_http_method_enm is an enumeration table for the http method used by a vault library when communicating with vault. '
    'It contains rows for representing the HTTP GET and the HTTP POST methods.';

  insert into credential_vault_http_method_enm (name)
  values
    ('GET'),
    ('POST');

  create table credential_vault_library (
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint credential_vault_store_fkey
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
    http_method text not null
      constraint credential_vault_http_method_enm_fkey
        references credential_vault_http_method_enm (name)
        on delete restrict
        on update cascade,
    http_request_body text
      constraint http_request_body_only_allowed_with_post_method
        check(
          http_request_body is null
          or
          (
            http_method = 'POST'
            and
            length(trim(http_request_body)) > 0
          )
        ),
    constraint credential_vault_library_store_id_name_uq
      unique(store_id, name),
    constraint credential_library_fkey
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

  create table credential_vault_lease (
    public_id wt_public_id primary key,
    library_id wt_public_id not null
      constraint credential_vault_library_fkey
        references credential_vault_library (public_id)
        on delete cascade
        on update cascade,
    session_id wt_public_id not null
      constraint session_fkey
        references session (public_id)
        on delete cascade
        on update cascade,
    token_hmac bytea not null
      constraint credential_vault_token_fkey
        references credential_vault_token (token_hmac)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    external_id text not null
      constraint credential_vault_lease_external_id_uq
        unique
      constraint external_id_must_not_be_empty
        check(length(trim(external_id)) > 0),
    last_renewal_time timestamp with time zone not null,
    expiration_time timestamp with time zone not null
      constraint last_renewal_time_must_be_before_expiration_time
        check(last_renewal_time < expiration_time),
    is_renewable boolean not null,
    constraint credential_dynamic_fkey
      foreign key (library_id, public_id)
      references credential_dynamic (library_id, public_id)
      on delete cascade
      on update cascade,
    constraint credential_vault_lease_library_id_public_id_uq
      unique(library_id, public_id)
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
    for each row execute procedure immutable_columns('external_id', 'library_id','session_id', 'create_time');

  create trigger insert_credential_dynamic_subtype before insert on credential_vault_lease
    for each row execute procedure insert_credential_dynamic_subtype();

  create trigger delete_credential_dynamic_subtype after delete on credential_vault_lease
    for each row execute procedure delete_credential_dynamic_subtype();

  insert into oplog_ticket (name, version)
  values
    ('credential_vault_store', 1),
    ('credential_vault_library', 1),
    ('credential_vault_lease', 1) ;

     create view credential_vault_store_client_private as
     with
     current_tokens as (
        select token_hmac,
               token, -- encrypted
               store_id,
               create_time,
               update_time,
               last_renewal_time,
               expiration_time,
               key_id,
               status
          from credential_vault_token
         where status = 'current'
     )
     select store.public_id         as public_id,
            store.scope_id          as scope_id,
            store.name              as name,
            store.description       as description,
            store.create_time       as create_time,
            store.update_time       as update_time,
            store.version           as version,
            store.vault_address     as vault_address,
            store.namespace         as namespace,
            store.ca_cert           as ca_cert,
            store.tls_server_name   as tls_server_name,
            store.tls_skip_verify   as tls_skip_verify,
            store.public_id         as store_id,
            token.token_hmac        as token_hmac,
            token.token             as ct_token, -- encrypted
            token.create_time       as token_create_time,
            token.update_time       as token_update_time,
            token.last_renewal_time as token_last_renewal_time,
            token.expiration_time   as token_expiration_time,
            token.key_id            as token_key_id,
            token.status            as token_status,
            cert.certificate        as client_cert,
            cert.certificate_key    as ct_client_key, -- encrypted
            cert.key_id             as client_key_id
       from credential_vault_store store
  left join current_tokens token
         on store.public_id = token.store_id
  left join credential_vault_client_certificate cert
         on store.public_id = cert.store_id;
  comment on view credential_vault_store_client_private is
    'credential_vault_store_client_private is a view where each row contains a credential store and the credential store''s data needed to connect to Vault. '
    'Each row may contain encrypted data. This view should not be used to retrieve data which will be returned external to boundary.';

     create view credential_vault_store_agg_public as
     select public_id,
            scope_id,
            name,
            description,
            create_time,
            update_time,
            version,
            vault_address,
            namespace,
            ca_cert,
            tls_server_name,
            tls_skip_verify,
            token_hmac,
            token_create_time,
            token_update_time,
            token_last_renewal_time,
            token_expiration_time,
            client_cert
       from credential_vault_store_client_private;
  comment on view credential_vault_store_agg_public is
    'credential_vault_store_agg_public is a view where each row contains a credential store. '
    'No encrypted data is returned. This view can be used to retrieve data which will be returned external to boundary.';

commit;
