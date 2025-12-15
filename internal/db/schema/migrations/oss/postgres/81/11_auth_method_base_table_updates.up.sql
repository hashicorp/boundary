-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add create_time, update_time and is_active_public_state to auth_method table.
  alter table auth_method
    add column create_time wt_timestamp,
    add column update_time wt_timestamp,
    add column is_active_public_state boolean not null default false
  ;

  -- Update rows with current values from LDAP auth method
  with
  sub_auth_method (public_id, create_time, update_time, is_active_public_state) as (
      select public_id,
             create_time,
             update_time,
             state = 'active-public'
        from auth_ldap_method
  )
  update auth_method
     set create_time            = sub_auth_method.create_time,
         update_time            = sub_auth_method.update_time,
         is_active_public_state = sub_auth_method.is_active_public_state
    from sub_auth_method
   where auth_method.public_id = sub_auth_method.public_id;

  -- Update rows with current values from OIDC auth method
  with
  sub_auth_method (public_id, create_time, update_time, is_active_public_state) as (
      select public_id,
             create_time,
             update_time,
             state = 'active-public'
        from auth_oidc_method
  )
  update auth_method
     set create_time            = sub_auth_method.create_time,
         update_time            = sub_auth_method.update_time,
         is_active_public_state = sub_auth_method.is_active_public_state
    from sub_auth_method
   where auth_method.public_id = sub_auth_method.public_id;

  -- Update rows with current values from password auth method
  with
  sub_auth_method (public_id, create_time, update_time, is_active_public_state) as (
      select public_id,
             create_time,
             update_time,
             true
        from auth_password_method
  )
  update auth_method
     set create_time            = sub_auth_method.create_time,
         update_time            = sub_auth_method.update_time,
         is_active_public_state = sub_auth_method.is_active_public_state
    from sub_auth_method
   where auth_method.public_id = sub_auth_method.public_id;

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
  create function insert_auth_method_password_subtype() returns trigger
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
      on auth_method (create_time desc, public_id desc);
  create index auth_method_update_time_public_id_idx
      on auth_method (update_time desc, public_id desc);

  analyze auth_method;

commit;
