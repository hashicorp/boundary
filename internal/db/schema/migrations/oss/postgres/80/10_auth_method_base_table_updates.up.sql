-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add create_time, update_time and is_active_public_state to auth_method table.
  alter table auth_method add column create_time wt_timestamp;
  alter table auth_method add column update_time wt_timestamp;
  alter table auth_method add column is_active_public_state boolean;

  -- Update rows with current values
     update auth_method
        set create_time            = ldap.create_time,
            update_time            = ldap.update_time,
            is_active_public_state = case 
                                      when ldap.state = 'active-public' then true
                                      else false
                                     end
       from auth_method as am
  left join auth_ldap_method as ldap
         on am.public_id = ldap.public_id;
  
     update auth_method
        set create_time            = oidc.create_time,
            update_time            = oidc.update_time,
            is_active_public_state = case 
                                      when oidc.state = 'active-public' then true
                                      else false
                                     end
       from auth_method as am
  left join auth_oidc_method as oidc
         on am.public_id = oidc.public_id;
  
     update auth_method
        set create_time            = pw.create_time,
            update_time            = pw.update_time,
            is_active_public_state = true
       from auth_method as am
  left join auth_password_method as pw
         on am.public_id = pw.public_id;

  -- Ensure that is_active_public_state is always set from now on
  alter table auth_method alter column is_active_public_state set not null;

  -- Replace the insert trigger to also set the create_time
  -- Partially replaces the insert_auth_method_subtype function defined in 2/10_auth.up.sql
  -- This is because ldap and oidc subtypes have a state column, but password does not.
  create or replace function insert_auth_method_subtype() returns trigger
  as $$
  begin
    insert into auth_method
      (public_id, scope_id, name, create_time, is_active_public_state)
    values
      (new.public_id, new.scope_id, new.name, new.create_time, new.state = 'active-public');
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_auth_method_subtype() is
    'insert_auth_method_subtype() inserts sub type name, create time, update time, '
    'and whether it is an active public state into the base type auth method table, '
    'specifically for ldap or oidc subtypes.';

  -- Replace the insert trigger to also set the create_time
  -- Partially replaces the insert_auth_method_subtype function defined in 2/10_auth.up.sql
  -- This is because ldap and oidc subtypes have a state column, but password does not.
  create or replace function insert_auth_method_password_subtype() returns trigger
  as $$
  begin
    insert into auth_method
      (public_id, scope_id, name, create_time, is_active_public_state)
    values
      (new.public_id, new.scope_id, new.name, new.create_time, true);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_auth_method_password_subtype() is
    'insert_auth_method_password_subtype() inserts sub type name, create time, update time, '
    'and that it is an active public state into the base type auth method table, '
    'specifically for the password subtype.';

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

  -- Add trigger to update the new is_active_public_state column on ldap and oidc subtype update.
  -- Password subtype has no state and will always be considered active public.
  create function update_auth_method_table_is_active_public_state() returns trigger
  as $$
  begin
    if new.state = 'active-public' then
      update auth_method set is_active_public_state = true where public_id = new.public_id;
      return new;
    else
      update auth_method set is_active_public_state = false where public_id = new.public_id;
      return new;
    end if;
  end;
  $$ language plpgsql;
  comment on function update_auth_method_table_is_active_public_state() is
    'update_auth_method_table_is_active_public_state is used to automatically update the '
    'is_active_public_state column of the base table whenever one of the subtype tables are updated';

  -- Add triggers to subtype tables
  create trigger update_auth_method_table_update_time before update on auth_ldap_method
    for each row execute procedure update_auth_method_table_update_time();
  create trigger update_auth_method_table_update_time before update on auth_oidc_method
    for each row execute procedure update_auth_method_table_update_time();
  create trigger update_auth_method_table_update_time before update on auth_password_method
    for each row execute procedure update_auth_method_table_update_time();

  -- Replace trigger on password subtype table
  drop trigger insert_auth_method_subtype on auth_password_method;
  create trigger insert_auth_method_password_subtype before insert on auth_password_method
    for each row execute procedure insert_auth_method_password_subtype();

  -- Add is_active_public_state triggers to ldap and oidc tables, as password has no state column.
  create trigger update_auth_method_table_is_active_public_state before update on auth_ldap_method
    for each row execute procedure update_auth_method_table_is_active_public_state();
  create trigger update_auth_method_table_is_active_public_state before update on auth_oidc_method
    for each row execute procedure update_auth_method_table_is_active_public_state();

  -- Add new indexes for the create and update time queries.
  create index auth_method_create_time_public_id_idx
      on auth_method (create_time desc, public_id asc);
  create index auth_method_update_time_public_id_idx
      on auth_method (update_time desc, public_id asc);

  analyze auth_method;

commit;