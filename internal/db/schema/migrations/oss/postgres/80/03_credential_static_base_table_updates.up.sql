-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add create_time and update_time to credential_static table.
  alter table credential_static add column create_time wt_timestamp;
  alter table credential_static add column update_time wt_timestamp;

  -- Update rows with current values
  update credential_static
    set create_time = csj.create_time, update_time = csj.update_time
    from credential_static as cs
    left join credential_static_json_credential as csj on cs.public_id = csj.public_id;
  update credential_static
    set create_time = cssshpk.create_time, update_time = cssshpk.update_time
    from credential_static as cs
    left join credential_static_ssh_private_key_credential as cssshpk on cs.public_id = cssshpk.public_id;
  update credential_static
    set create_time = csupw.create_time, update_time = csupw.update_time
    from credential_static as cs
    left join credential_static_username_password_credential as csupw on cs.public_id = csupw.public_id;

  -- Replace the insert trigger to also set the create_time
  -- Replaces the insert_credential_static_subtype function defined in 46/01_credentials.up.sql
  create or replace function insert_credential_static_subtype() returns trigger
  as $$
  begin
    select project_id into new.project_id
      from credential_store
     where credential_store.public_id = new.store_id;

    insert into credential_static
      (public_id, store_id, project_id, create_time)
    values
      (new.public_id, new.store_id, new.project_id, new.create_time);
    return new;
  end;
  $$ language plpgsql;

  -- Add trigger to update the new update_time column on every subtype update.
  create function update_credential_static_table_update_time() returns trigger
  as $$
  begin
    update credential_static set update_time = now() where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_credential_static_table_update_time() is
    'update_credential_static_table_update_time is used to automatically update the update_time '
    'of the base table whenever one of the subtype tables are updated';

  -- Add triggers to subtype tables
  create trigger update_credential_static_table_update_time before update on credential_static_json_credential
    for each row execute procedure update_credential_static_table_update_time();
  create trigger update_credential_static_table_update_time before update on credential_static_ssh_private_key_credential
    for each row execute procedure update_credential_static_table_update_time();
  create trigger update_credential_static_table_update_time before update on credential_static_username_password_credential
    for each row execute procedure update_credential_static_table_update_time();

  -- Add new indexes for the create and update time queries.
  create index credential_static_create_time_public_id_idx
      on credential_static (create_time desc, public_id asc);
  create index credential_static_update_time_public_id_idx
      on credential_static (update_time desc, public_id asc);

  analyze credential_static;

commit;
