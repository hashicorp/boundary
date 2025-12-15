-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- credential_store
  create table credential_store (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
        references iam_scope (public_id)
        on delete cascade
        on update cascade,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    constraint credential_store_scope_id_public_id_uq
      unique(scope_id, public_id)
  );
  comment on table credential_store is
    'credential_store is a base table for the credential store type. '
    'Each row is owned by a single scope and maps 1-to-1 to a row in one of the credential store subtype tables.';

  create trigger immutable_columns before update on credential_store
    for each row execute procedure immutable_columns('public_id', 'scope_id');

  -- insert_credential_store_subtype() is a before insert trigger
  -- function for subtypes of credential_store
  -- Replaced in 44/01_credentials.up.sql
  create function insert_credential_store_subtype() returns trigger
  as $$
  begin
    insert into credential_store
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_credential_store_subtype() is an after delete trigger
  -- function for subtypes of credential_store
  create function delete_credential_store_subtype() returns trigger
  as $$
  begin
    delete from credential_store
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  -- credential_library
  create table credential_library (
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint credential_store_fkey
        references credential_store (public_id)
        on delete cascade
        on update cascade,
    constraint credential_library_store_id_public_id_uq
      unique(store_id, public_id)
  );
  comment on table credential_library is
    'credential_library is a base table for the credential library type and a child table of credential_store. '
    'Each row maps 1-to-1 to a row in one of the credential library subtype tables.';

  create trigger immutable_columns before update on credential_library
    for each row execute procedure immutable_columns('public_id', 'store_id');

  -- insert_credential_library_subtype() is a before insert trigger
  -- function for subtypes of credential_library
  create function insert_credential_library_subtype() returns trigger
  as $$
  begin
    insert into credential_library
      (public_id, store_id)
    values
      (new.public_id, new.store_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_credential_library_subtype() is an after delete trigger
  -- function for subtypes of credential_library
  create function delete_credential_library_subtype() returns trigger
  as $$
  begin
    delete from credential_library
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  -- credential
  create table credential (
    public_id wt_public_id primary key
  );
  comment on table credential is
    'credential is a base table for the credential type. ';

  create trigger immutable_columns before update on credential
    for each row execute procedure immutable_columns('public_id');

  -- insert_credential_subtype() is a before insert trigger
  -- function for subtypes of credential
  create function insert_credential_subtype() returns trigger
  as $$
  begin
    insert into credential
      (public_id)
    values
      (new.public_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_credential_subtype() is an after delete trigger
  -- function for subtypes of credential
  create function delete_credential_subtype() returns trigger
  as $$
  begin
    delete from credential
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  -- credential_static
  create table credential_static (
    public_id wt_public_id primary key
      constraint credential_fkey
        references credential (public_id)
        on delete cascade
        on update cascade,
    store_id wt_public_id not null
      constraint credential_store_fkey
        references credential_store (public_id)
        on delete cascade
        on update cascade,
    constraint credential_static_store_id_public_id_uq
      unique(store_id, public_id)
  );
  comment on table credential_static is
    'credential_static is a base table for the credential static type. '
    'It is a credential subtype and a child table of credential_store. ';

  create trigger immutable_columns before update on credential_static
    for each row execute procedure immutable_columns('public_id', 'store_id');

  create trigger insert_credential_subtype before insert on credential_static
    for each row execute procedure insert_credential_subtype();

  create trigger delete_credential_subtype after delete on credential_static
    for each row execute procedure delete_credential_subtype();

  -- insert_credential_static_subtype() is a before insert trigger
  -- function for subtypes of credential_static
  -- Replaced in 46/01_credential.up.sql
  create function insert_credential_static_subtype() returns trigger
  as $$
  begin
    insert into credential_static
      (public_id, store_id)
    values
      (new.public_id, new.store_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_credential_static_subtype() is an after delete trigger
  -- function for subtypes of credential_static
  create function delete_credential_static_subtype() returns trigger
  as $$
  begin
    delete from credential_static
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  -- credential_dynamic
  create table credential_dynamic (
    public_id wt_public_id primary key
      constraint credential_fkey
        references credential (public_id)
        on delete cascade
        on update cascade,
    library_id wt_public_id not null
      constraint credential_library_fkey
        references credential_library (public_id)
        on delete cascade
        on update cascade,
    constraint credential_dynamic_library_id_public_id_uq
      unique(library_id, public_id)
  );
  comment on table credential_dynamic is
    'credential_dynamic is a base table for the credential dynamic type. '
    'It is a credential subtype and a child table of credential_library. ';

  create trigger immutable_columns before update on credential_dynamic
    for each row execute procedure immutable_columns('public_id', 'library_id');

  create trigger insert_credential_subtype before insert on credential_dynamic
    for each row execute procedure insert_credential_subtype();

  create trigger delete_credential_subtype after delete on credential_dynamic
    for each row execute procedure delete_credential_subtype();

  -- insert_credential_dynamic_subtype() is a before insert trigger
  -- function for subtypes of credential_dynamic
  create function insert_credential_dynamic_subtype() returns trigger
  as $$
  begin
    insert into credential_dynamic
      (public_id, library_id)
    values
      (new.public_id, new.library_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_credential_dynamic_subtype() is an after delete trigger
  -- function for subtypes of credential_dynamic
  create function delete_credential_dynamic_subtype() returns trigger
  as $$
  begin
    delete from credential_dynamic
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  create table credential_purpose_enm (
    name text primary key
      -- This constraint is updated in 40/01_credential.up.sql
      constraint only_predefined_credential_purposes_allowed
      check (
        name in (
          'application',
          'ingress',
          'egress'
        )
      )
  );
  comment on table credential_purpose_enm is
    'credential_purpose_enm is an enumeration table for credential purposes. '
    'It contains rows for representing the application, egress, and ingress credential purposes.';

  -- These values are updated in 40/01_credential.up.sql
  insert into credential_purpose_enm (name)
  values
    ('application'),
    ('ingress'),
    ('egress');

commit;
