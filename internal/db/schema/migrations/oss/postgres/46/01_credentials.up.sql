-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- credential_library
  alter table credential_library
    add column project_id wt_public_id,
    add constraint credential_library_project_id_public_id_uq
      unique(project_id, public_id)
  ;

  update credential_library
     set (project_id) =
         (select project_id
            from credential_store
           where credential_store.public_id = credential_library.store_id
         )
  ;

  alter table credential_library
    alter column project_id set not null,
    drop constraint credential_store_fkey,
    add constraint credential_store_fkey
      foreign key (project_id, store_id)
        references credential_store (project_id, public_id)
        on delete cascade
        on update cascade,
    -- The name of this constraint does not follow our naming conventions for
    -- unique constraints because it would be to long. The max length for
    -- identifiers in PostgreSQL is 63 characters.
    -- credential_library_project_id_store_id_public_id_credential_type_uq
    -- is 67 characters.
    --
    -- https://www.postgresql.org/docs/current/limits.html
    --
    -- Replaces credential_library_store_id_public_id_credential_type_uq
    add constraint credential_library_project_store_public_ids_credential_type_uq
      unique(project_id, store_id, public_id, credential_type)
  ;

  drop trigger immutable_columns on credential_library;
  create trigger immutable_columns before update on credential_library
    for each row execute function immutable_columns('public_id', 'store_id', 'project_id', 'credential_type');

  -- insert_credential_library_subtype() is a before insert trigger
  -- function for subtypes of credential_library.
  -- Replaces the insert_credential_library_subtype function defined in 22/02_credential_type.up.sql
  -- Replaced in 81/04_credential_library_base_table_updates.up.sql
  create or replace function insert_credential_library_subtype() returns trigger
  as $$
  begin

    select project_id into new.project_id
      from credential_store
     where credential_store.public_id = new.store_id;

    insert into credential_library
      (public_id, store_id, project_id, credential_type)
    values
      (new.public_id, new.store_id, new.project_id, new.credential_type);
    return new;
  end;
  $$ language plpgsql;

  -- credential_static
  alter table credential_static
    add column project_id wt_public_id,
    add constraint credential_static_project_id_public_id_uq
      unique(project_id, public_id)
  ;

  update credential_static
     set (project_id) =
         (select project_id
            from credential_store
           where credential_store.public_id = credential_static.store_id
         )
  ;

  alter table credential_static
    alter column project_id set not null,
    drop constraint credential_store_fkey,
    add constraint credential_store_fkey
      foreign key (project_id, store_id)
        references credential_store (project_id, public_id)
        on delete cascade
        on update cascade,
    -- Replaces credential_static_store_id_public_id_uq
    add constraint credential_static_project_id_store_id_public_id_uq
      unique(project_id, store_id, public_id)
  ;

  drop trigger immutable_columns on credential_static;
  create trigger immutable_columns before update on credential_static
    for each row execute function immutable_columns('public_id', 'store_id', 'project_id');

  -- insert_credential_static_subtype() is a before insert trigger
  -- function for subtypes of credential_static
  -- Replaces the insert_credential_static_subtype function defined in 10/03_credential.up.sql
  -- Replaced in 81/03_credential_static_base_table_updates.up.sql
  create or replace function insert_credential_static_subtype() returns trigger
  as $$
  begin

    select project_id into new.project_id
      from credential_store
     where credential_store.public_id = new.store_id;

    insert into credential_static
      (public_id, store_id, project_id)
    values
      (new.public_id, new.store_id, new.project_id);
    return new;
  end;
  $$ language plpgsql;

  -- credential_vault_library
  alter table credential_vault_library
    add column project_id wt_public_id
  ;

  update credential_vault_library
     set (project_id) =
         (select project_id
            from credential_library
           where credential_library.public_id = credential_vault_library.public_id
         )
  ;

  alter table credential_vault_library
    alter column project_id set not null,
    drop constraint credential_library_fkey,
    add constraint credential_library_fkey
      foreign key (project_id, store_id, public_id, credential_type)
        references credential_library (project_id, store_id, public_id, credential_type)
        on delete cascade
        on update cascade
  ;

  drop trigger immutable_columns on credential_vault_library;
  create trigger immutable_columns before update on credential_vault_library
    for each row execute function immutable_columns('public_id', 'store_id', 'project_id', 'credential_type', 'create_time');

  -- credential_static_username_password_credential
  alter table credential_static_username_password_credential
    add column project_id wt_public_id
  ;

  update credential_static_username_password_credential
     set (project_id) =
         (select project_id
            from credential_static
           where credential_static.public_id = credential_static_username_password_credential.public_id
         )
  ;

  alter table credential_static_username_password_credential
    alter column project_id set not null,
    drop constraint credential_static_fkey,
    add constraint credential_static_fkey
      foreign key (project_id, store_id, public_id)
        references credential_static (project_id, store_id, public_id)
        on delete cascade
        on update cascade
  ;

  drop trigger immutable_columns on credential_static_username_password_credential;
  create trigger immutable_columns before update on credential_static_username_password_credential
    for each row execute function immutable_columns('public_id', 'store_id', 'project_id', 'create_time');

  -- credential_static_ssh_private_key_credential
  alter table credential_static_ssh_private_key_credential
    add column project_id wt_public_id
  ;

  update credential_static_ssh_private_key_credential
     set (project_id) =
         (select project_id
            from credential_static
           where credential_static.public_id = credential_static_ssh_private_key_credential.public_id
         )
  ;

  alter table credential_static_ssh_private_key_credential
    alter column project_id set not null,
    drop constraint credential_static_fkey,
    add constraint credential_static_fkey
      foreign key (project_id, store_id, public_id)
        references credential_static (project_id, store_id, public_id)
        on delete cascade
        on update cascade
  ;

  drop trigger immutable_columns on credential_static_ssh_private_key_credential;
  create trigger immutable_columns before update on credential_static_ssh_private_key_credential
    for each row execute function immutable_columns('public_id', 'store_id', 'project_id', 'create_time');

  alter table credential_library
    drop constraint credential_library_store_id_public_id_credential_type_uq
  ;

  alter table credential_static
    drop constraint credential_static_store_id_public_id_uq
  ;

commit;
