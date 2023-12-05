-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add create_time and update_time to credential_store table.
  alter table credential_store add column create_time wt_timestamp;
  alter table credential_store add column update_time wt_timestamp;

  -- Update rows with current values
  update credential_store
    set create_time = cvs.create_time, update_time = cvs.update_time
    from credential_store as cl
    left join credential_vault_store as cvs on cl.public_id = cvs.public_id;
  update credential_store
    set create_time = css.create_time, update_time = css.update_time
    from credential_store as cl
    left join credential_static_store as css on cl.public_id = css.public_id;

  -- Replace the insert trigger to also set the create_time
  -- Replaces the insert_credential_store_subtype function defined in 44/01_credentials.up.sql
   create or replace function insert_credential_store_subtype() returns trigger
  as $$
  begin
    insert into credential_store
      (public_id, project_id, create_time)
    values
      (new.public_id, new.project_id, new.create_time);
    return new;
  end;
  $$ language plpgsql;

  -- Add trigger to update the new update_time column on every subtype update.
  create function update_credential_store_table_update_time() returns trigger
  as $$
  begin
    update credential_store set update_time = now() where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_credential_store_table_update_time() is
    'update_credential_store_table_update_time is used to automatically update the update_time '
    'of the base table whenever one of the subtype tables are updated';

  -- Add triggers to subtype tables
  create trigger update_credential_store_table_update_time before update on credential_vault_store
    for each row execute procedure update_credential_store_table_update_time();
  create trigger update_credential_store_table_update_time before update on credential_static_store
    for each row execute procedure update_credential_store_table_update_time();

  -- Add new indexes for the create and update time queries.
  create index credential_store_create_time_public_id_idx
      on credential_store (create_time desc, public_id asc);
  create index credential_store_update_time_public_id_idx
      on credential_store (update_time desc, public_id asc);

  analyze credential_store;

commit;
