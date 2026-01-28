-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- We are updating the plugin table here to have a scope id, since
  -- subtypes of plugin should be scoped.  We use 'global' as the default
  -- just for the purpose of the migration since the scope cannot be null
  -- and the one plugin that already exists (pi_system) can be globally
  -- scoped.  The immediately following statement removes this default.
  -- We add a name so we can enforce that all plugins have a unique name
  -- in a specific scope across all plugin subtypes.
  alter table plugin
    add column name wt_name,
    add column scope_id wt_scope_id not null default 'global'
      constraint iam_scope_global_fkey
      references iam_scope_global(scope_id)
        on delete cascade
        on update cascade;

  alter table plugin
    alter column scope_id drop default;

  -- Add constraints that enforce names are unique across all plugin subtypes
  -- in a specific scope.
  alter table plugin
    add constraint plugin_scope_id_public_id_uq
      unique (scope_id, public_id),
    add constraint plugin_scope_id_name_uq
      unique (scope_id, name);


  -- insert, update, and delete plugin_subtypes are created since we are adding
  -- subtyped plugins and we need to keep the base table plugin in sync with all
  -- subtype tables.
  create function insert_plugin_subtype() returns trigger
  as $$
  begin
    insert into plugin
    (public_id, scope_id, name)
    values
      (new.public_id, new.scope_id, new.name);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_plugin_subtype() is
    'insert_plugin_subtype() inserts sub type name into the base type plugin table';

  create function update_plugin_subtype() returns trigger
  as $$
  begin
    update plugin set name = new.name where public_id = new.public_id and new.name != name;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_plugin_subtype() is
    'update_plugin_subtype() will update base plugin type name column with new values from sub type';

  -- delete_plugin_subtype() is an after delete trigger function
  -- for subtypes of plugin
  create function delete_plugin_subtype() returns trigger
  as $$
  begin
    delete from plugin
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_plugin_subtype is
    'delete_plugin_subtype() is an after trigger function for subytypes of plugin';

  insert into oplog_ticket (name, version)
  values
    ('plugin', 1);

commit;
