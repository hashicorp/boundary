begin;

  create table vault_credential_store (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fk
        references iam_scope (public_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    token_role_path text not null
      constraint token_role_path_must_not_be_empty
        check(length(trim(token_role_path)) > 0),
    namespace text,
    constraint credential_store_fk
      foreign key (scope_id, public_id)
      references credential_store (scope_id, public_id)
      on delete cascade
      on update cascade,
    constraint vault_credential_store_scope_id_name_uq
      unique(scope_id, name)
  );

  create trigger update_version_column after update on vault_credential_store
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on vault_credential_store
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on vault_credential_store
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on vault_credential_store
    for each row execute procedure immutable_columns('public_id', 'scope_id','create_time');

  create trigger insert_credential_store_subtype before insert on vault_credential_store
    for each row execute procedure insert_credential_store_subtype();

  create trigger delete_credential_store_subtype after delete on vault_credential_store
    for each row execute procedure delete_credential_store_subtype();

  create table vault_credential_library (
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint vault_credential_store_fk
        references vault_credential_store (public_id)
        on delete cascade
        on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    vault_path text not null
      constraint vault_path_must_not_be_empty
        check(length(trim(vault_path)) > 0),
    constraint vault_credential_library_store_id_name_uq
      unique(store_id, name),
    constraint credential_library_fk
      foreign key (store_id, public_id)
      references credential_library (store_id, public_id)
      on delete cascade
      on update cascade,
    constraint vault_credential_library_store_id_public_id_uq
      unique(store_id, public_id)
  );

  create trigger update_version_column after update on vault_credential_library
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on vault_credential_library
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on vault_credential_library
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on vault_credential_library
    for each row execute procedure immutable_columns('public_id', 'store_id','create_time');

  create trigger insert_credential_library_subtype before insert on vault_credential_library
    for each row execute procedure insert_credential_library_subtype();

  create trigger delete_credential_library_subtype after delete on vault_credential_library
    for each row execute procedure delete_credential_library_subtype();

  create table vault_credential_token (
    vault_token text primary key
      constraint vault_token_must_not_be_empty
        check(length(trim(vault_token)) > 0),
    store_id wt_public_id not null
      constraint vault_credential_store_fk
        references vault_credential_store (public_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    accessor text not null
      constraint vault_credential_token_accessor_uq
        unique
      constraint accessor_must_not_be_empty
        check(length(trim(accessor)) > 0),
    lease_duration int not null
      constraint lease_duration_must_not_be_negative
        check(lease_duration >= 0),
    last_renewal_time wt_timestamp not null
  );

  create trigger update_version_column after update on vault_credential_token
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on vault_credential_token
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on vault_credential_token
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on vault_credential_token
    for each row execute procedure immutable_columns('vault_token', 'store_id','create_time', 'accessor');

  create table vault_credential_lease (
    lease_id text primary key
      constraint lease_id_must_not_be_empty
        check(length(trim(lease_id)) > 0),
    library_id wt_public_id not null
      constraint vault_credential_library_fk
        references vault_credential_library (public_id)
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
    lease_duration int not null
      constraint lease_duration_must_not_be_negative
        check(lease_duration >= 0),
    last_renewal_time wt_timestamp not null,
    is_renewable boolean not null
  );

  create trigger update_version_column after update on vault_credential_lease
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on vault_credential_lease
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on vault_credential_lease
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on vault_credential_lease
    for each row execute procedure immutable_columns('lease_id', 'library_id','session_id', 'create_time');

  insert into oplog_ticket (name, version)
  values
    ('vault_credential_store', 1),
    ('vault_credential_library', 1);

commit;
