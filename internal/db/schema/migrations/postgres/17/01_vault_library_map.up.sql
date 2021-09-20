begin;

  create table credential_vault_library_map (
    private_id wt_private_id,
    library_id wt_public_id
      constraint credential_vault_library_fk
        references credential_vault_library (public_id)
        on delete cascade
        on update cascade,
    primary key (private_id, library_id),
    constraint credential_vault_library_map_library_id_uq
      unique(library_id)
  );
  comment on table credential_vault_library_map is
    'credential_vault_library_map is a base table for the vault library map type. '
    'Each row is owned by a single vault library and maps 1-to-1 to a row in one of the vault library map subtype tables.';

  create trigger immutable_columns before update on credential_vault_library_map
    for each row execute procedure immutable_columns('private_id', 'library_id');


  -- insert_credential_vault_library_map_subtype() is a before insert trigger
  -- function for subtypes of credential_vault_library_map
  create function insert_credential_vault_library_map_subtype()
    returns trigger
  as $$
  begin
    insert into credential_vault_library_map
      (private_id, library_id)
    values
      (new.private_id, new.library_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_credential_vault_library_map_subtype() is an after delete trigger
  -- function for subtypes of credential_vault_library_map
  create function delete_credential_vault_library_map_subtype()
    returns trigger
  as $$
  begin
    delete from credential_vault_library_map
    where private_id = old.private_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

commit;
