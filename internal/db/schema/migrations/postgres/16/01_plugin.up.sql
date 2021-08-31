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
    add column scope_id wt_scope_id
      not null
      default 'global'
      references iam_scope(public_id)
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
  create or replace function insert_plugin_subtype()
    returns trigger
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

  create or replace function
    update_plugin_subtype()
    returns trigger
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
  create or replace function delete_plugin_subtype()
    returns trigger
  as $$
  begin
    delete from plugin
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_plugin_subtype is
    'delete_plugin_subtype() is an after trigger function for subytypes of plugin';

  /*
    ┌──────────────────┐         ┌───────────────────┐
    │      plugin      │         │  plugin_version   │
    ├──────────────────┤         ├───────────────────┤
    │public_id (pk)    │        ╱│public_id (pk)     │
    │scope_id (fk)     │┼┼────┼──│plugin_id (fk)     │
    └──────────────────┘        ╲│semantic_version   │
                                 └───────────────────┘
                                           ┼
                                           ┼
                                           │
                                           ┼
                                          ╱│╲
                               ┌──────────────────────┐
                               │  plugin_executable   │
                               ├──────────────────────┤
                               │version_id (pk, fk)   │
                               │operating_system (pk) │
                               │architecture (pk)     │
                               │executable            │
                               └──────────────────────┘
   */
  create table plugin_version (
    public_id wt_public_id primary key,
    plugin_id wt_public_id not null
      constraint plugin_fkey
        references plugin (public_id)
        on delete cascade
        on update cascade,
    semantic_version text not null
      constraint plugin_version_requires_semantic_version
      check(length(semantic_version) > 4), -- minimum length is length("0.0.0")
    create_time wt_timestamp,

    unique(plugin_id, public_id),
    unique(plugin_id, semantic_version)
  );

  create trigger default_create_time_column before insert on plugin_version
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on plugin_version
    for each row execute procedure immutable_columns('public_id', 'plugin_id', 'create_time', 'semantic_version');

  create table plugin_executable (
    version_id wt_public_id
      references plugin_version(public_id)
        on delete cascade
        on update cascade,
    operating_system text not null
      constraint operating_system_is_not_empty
        check(length(operating_system) > 0),
    architecture text not null
      constraint architecture_is_not_empty
        check(length(architecture) > 0),
    executable bytea not null
      constraint executable_is_not_empty
      check(length(executable) > 0),
    create_time wt_timestamp,

    primary key(operating_system, architecture, version_id)
  );

  create trigger default_create_time_column before insert on plugin_executable
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on plugin_executable
    for each row execute procedure immutable_columns('version_id', 'operating_system', 'architecture', 'executable');

  insert into oplog_ticket (name, version)
  values
    ('plugin', 1),
    ('plugin_version', 1),
    ('plugin_executable', 1);

commit;
