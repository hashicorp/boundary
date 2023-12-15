-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add create_time and update_time to auth_method table.
  alter table auth_method add column create_time wt_timestamp;
  alter table auth_method add column update_time wt_timestamp;

  -- Update rows with current values
  update auth_method
    set create_time = ldap.create_time, update_time = ldap.update_time
    from auth_method as am
    left join auth_ldap_method as ldap on am.public_id = ldap.public_id;
  update auth_method
    set create_time = oidc.create_time, update_time = oidc.update_time
    from auth_method as am
    left join auth_oidc_method as oidc on am.public_id = oidc.public_id;
  update auth_method
    set create_time = pw.create_time, update_time = pw.update_time
    from auth_method as am
    left join auth_password_method as pw on am.public_id = pw.public_id;

  -- Replace the insert trigger to also set the create_time
  -- Replaces the insert_auth_method_subtype function defined in 2/10_auth.up.sql
   create or replace function insert_auth_method_subtype() returns trigger
  as $$
  begin
    insert into auth_method
      (public_id, scope_id, name, create_time)
    values
      (new.public_id, new.scope_id, new.name, new.create_time);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_auth_method_subtype() is
    'insert_auth_method_subtype() inserts sub type name and create time into '
    'the base type auth method table';

  -- Add trigger to update the new update_time column on every subtype update.
  create function update_auth_method_table_update_time() returns trigger
  as $$
  begin
    update auth_method set update_time = now() where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_auth_method_table_update_time() is
    'update_auth_method_table_update_time is used to automatically update the update_time '
    'of the base table whenever one of the subtype tables are updated';

  -- Add triggers to subtype tables
  create trigger update_auth_method_table_update_time before update on auth_ldap_method
    for each row execute procedure update_auth_method_table_update_time();
  create trigger update_auth_method_table_update_time before update on auth_oidc_method
    for each row execute procedure update_auth_method_table_update_time();
  create trigger update_auth_method_table_update_time before update on auth_password_method
    for each row execute procedure update_auth_method_table_update_time();

  -- Add new indexes for the create and update time queries.
  create index auth_method_create_time_public_id_idx
      on auth_method (create_time desc, public_id asc);
  create index auth_method_update_time_public_id_idx
      on auth_method (update_time desc, public_id asc);

  analyze auth_method;

commit;