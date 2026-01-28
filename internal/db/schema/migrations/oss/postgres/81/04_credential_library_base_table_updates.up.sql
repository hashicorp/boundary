-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add create_time and update_time to credential_library table.
  alter table credential_library
    add column create_time wt_timestamp,
    add column update_time wt_timestamp;

  -- Update rows with current values from the subtype credential library tables.
  with sub_credential_library as (
    select public_id,
           create_time,
           update_time
      from credential_vault_library
     union
    select public_id,
           create_time,
           update_time
      from credential_vault_ssh_cert_library
  )
  update credential_library
     set create_time = sub_credential_library.create_time,
         update_time = sub_credential_library.update_time
    from sub_credential_library
   where credential_library.public_id = sub_credential_library.public_id;

  alter table credential_library
    alter column create_time set not null,
    alter column update_time set not null;

  -- Replace the insert trigger to also set the create_time
  -- Replaces the insert_credential_library_subtype function defined in 46/01_credentials.up.sql
  create or replace function insert_credential_library_subtype() returns trigger
  as $$
  begin
    select project_id into new.project_id
      from credential_store
     where credential_store.public_id = new.store_id;

    insert into credential_library
      (public_id, store_id, project_id, credential_type, create_time)
    values
      (new.public_id, new.store_id, new.project_id, new.credential_type, new.create_time);
    return new;
  end;
  $$ language plpgsql;

  -- Add trigger to update the new update_time column on every subtype update.
  create function update_credential_library_table_update_time() returns trigger
  as $$
  begin
    update credential_library set update_time = now() where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_credential_library_table_update_time() is
    'update_credential_library_table_update_time is used to automatically update the update_time '
    'of the base table whenever one of the subtype tables are updated';

  -- Add triggers to subtype tables
  create trigger update_credential_library_table_update_time before update on credential_vault_library
    for each row execute procedure update_credential_library_table_update_time();
  create trigger update_credential_library_table_update_time before update on credential_vault_ssh_cert_library
    for each row execute procedure update_credential_library_table_update_time();

  -- Add new indexes for the create and update time queries.
  create index credential_library_create_time_public_id_idx
      on credential_library (create_time desc, public_id desc);
  create index credential_library_update_time_public_id_idx
      on credential_library (update_time desc, public_id desc);

  analyze credential_library;

commit;
