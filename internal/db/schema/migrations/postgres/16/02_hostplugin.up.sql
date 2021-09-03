begin;

/*
  ┌──────────────────┐
  │      plugin      │
  ├──────────────────┤
  │public_id (pk)    │
  │scope_id (fk)     │
  └──────────────────┘
            ┼
            ┼
            │
            ┼
            ┼
  ┌──────────────────┐
  │   plugin_host    │
  ├──────────────────┤
  │public_id (pk)    │
  │scope_id (fk)     │
  │name              │
  │description       │
  │version           │
  │plugin_name       │
  │id_prefix         │
  │semantic_version  │
  └──────────────────┘
*/
  create table plugin_host (
    public_id wt_plugin_id primary key,
    scope_id wt_scope_id not null
    -- TODO: Allow plugins to be created in different scopes and
    --     constrain the host-catalog's plugin reference accordingly.
    constraint plugins_must_be_global
      references iam_scope_global(scope_id)
      on delete cascade
      on update cascade,
    name wt_name,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    plugin_name text not null
      constraint plugin_name_must_be_not_empty
        check(length(trim(plugin_name)) > 0)
      constraint plugin_name_must_be_lowercase
        check(lower(trim(plugin_name)) = plugin_name)
      constraint plugin_name_must_be_unique
        unique,
    id_prefix text not null
      constraint plugin_id_prefix_must_be_not_empty
        check(length(trim(id_prefix)) > 0)
      constraint plugin_id_prefix_must_fit_format
        check (id_prefix ~ '^[a-z0-9]*$')
      constraint plugin_id_prefix_must_be_unique
        unique,
    foreign key (scope_id, public_id)
      references plugin(scope_id, public_id)
      on delete cascade
      on update cascade,
    unique(scope_id, name)
  );

  create trigger update_version_column after update on plugin_host
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on plugin_host
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on plugin_host
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on plugin_host
    for each row execute procedure immutable_columns('public_id', 'create_time', 'plugin_name');

  create trigger insert_plugin_subtype before insert on plugin_host
    for each row execute procedure insert_plugin_subtype();

  create trigger update_plugin_subtype before update on plugin_host
    for each row execute procedure update_plugin_subtype();

  create trigger delete_plugin_subtype after delete on plugin_host
    for each row execute procedure delete_plugin_subtype();

  insert into oplog_ticket (name, version)
  values
    ('plugin_host', 1);

commit;
