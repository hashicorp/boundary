begin;

  -- credential_store
  create table credential_store (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fk
        references iam_scope (public_id)
        on delete cascade
        on update cascade,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    constraint credential_store_scope_id_public_id_uq
      unique(scope_id, public_id)
  );

  create trigger immutable_columns before update on credential_store
    for each row execute procedure immutable_columns('public_id', 'scope_id');

  -- insert_credential_store_subtype() is a before insert trigger
  -- function for subtypes of credential_store
  create or replace function insert_credential_store_subtype()
    returns trigger
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
  create or replace function delete_credential_store_subtype()
    returns trigger
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
      constraint credential_store_fk
        references credential_store (public_id)
        on delete cascade
        on update cascade,
    constraint credential_library_store_id_public_id_uq
      unique(store_id, public_id)
  );

  create trigger immutable_columns before update on credential_library
    for each row execute procedure immutable_columns('public_id', 'store_id');

  -- insert_credential_library_subtype() is a before insert trigger
  -- function for subtypes of credential_library
  create or replace function insert_credential_library_subtype()
    returns trigger
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
  create or replace function delete_credential_library_subtype()
    returns trigger
  as $$
  begin
    delete from credential_library
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  insert into oplog_ticket (name, version)
  values
    ('credential_store', 1),
    ('credential_library', 1);

commit;
