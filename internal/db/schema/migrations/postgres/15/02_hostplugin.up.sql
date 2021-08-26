begin;

/*
  ┌──────────────────┐         ┌───────────────────┐
  │      plugin      │         │  plugin_version   │
  ├──────────────────┤         ├───────────────────┤
  │public_id (pk)    │        ╱│public_id (pk)     │
  │scope_id (fk)     │┼┼────┼──│plugin_id (fk)     │
  └──────────────────┘        ╲│semantic_version   │
            ┼                  └───────────────────┘
            ┼                            ┼
            │                            ┼
            ┼                            │
            ┼                            ┼
  ┌──────────────────┐                  ╱│╲
  │   host_plugin    │       ┌──────────────────────┐
  ├──────────────────┤       │    plugin_binary     │
  │public_id (pk)    │       ├──────────────────────┤
  │scope_id (fk)     │       │version_id (pk, fk)   │
  │name              │       │operating_system (pk) │
  │description       │       │architecture (pk)     │
  │version           │       │executable            │
  │plugin_name       │       └──────────────────────┘
  └──────────────────┘
*/
  create table host_plugin (
    public_id wt_plugin_id primary key,
    scope_id wt_scope_id,
    name wt_name,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    plugin_name text
      not null
      constraint plugin_name_must_be_not_empty
        check(length(trim(plugin_name)) > 0)
      unique,
    foreign key (scope_id, public_id)
      references plugin(scope_id, public_id)
      on delete cascade
      on update cascade,
    unique(scope_id, name)
  );

  create trigger update_version_column after update on host_plugin
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on host_plugin
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin
    for each row execute procedure immutable_columns('public_id', 'create_time', 'plugin_name');

  create trigger insert_plugin_subtype before insert on host_plugin
    for each row execute procedure insert_plugin_subtype();

  create trigger update_plugin_subtype before update on host_plugin
    for each row execute procedure update_plugin_subtype();

  create trigger delete_plugin_subtype after delete on host_plugin
    for each row execute procedure delete_plugin_subtype();

  insert into oplog_ticket (name, version)
  values
    ('host_plugin', 1);

commit;
