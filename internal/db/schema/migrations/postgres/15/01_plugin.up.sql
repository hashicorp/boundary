begin;

/*
     ┌──────────────────┐
     │   host_plugin    │
     ├──────────────────┤         ┌───────────────────┐
     │public_id (pk)    │         │host_plugin_version│
     │name              │         ├───────────────────┤
     │id_prefix         │         │public_id (pk)     │
     │scope_id          │┼┼─────┼┼│plugin_id (fk)     │
     │description       │         │version            │
     │version           │         └───────────────────┘
     │                  │
     └──────────────────┘
               ┼
               ┼
               │
               ○
              ╱│╲
  ┌─────────────────────────┐
  │   plugin_host_catalog   │
  ├─────────────────────────┤
  │public_id (pk)           │
  │plugin_id (fk)           │
  │...                      │
  └─────────────────────────┘

*/

  create table host_plugin (
    public_id wt_plugin_id
      primary key,
    scope_id wt_scope_id -- this should always be global for now
      not null
      references iam_scope (public_id)
      on delete cascade
      on update cascade,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    name text
      not null
      constraint name_must_be_not_empty
        check(length(trim(name)) > 0)
      unique,
    id_prefix text
      not null
      constraint id_prefix_must_be_not_empty
        check(length(trim(id_prefix)) > 0)
      unique
  );

  create trigger update_version_column after update on host_plugin
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on host_plugin
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin
    for each row execute procedure immutable_columns('public_id', 'scope_id','create_time', 'name', 'id_prefix');

  create table host_plugin_version (
    public_id wt_public_id primary key,
    plugin_id wt_public_id not null
      references host_plugin (public_id)
      on delete cascade
      on update cascade,
    version text,
    create_time wt_timestamp,
    update_time wt_timestamp,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(plugin_id, public_id),
    unique(plugin_id, version)
  );

  create trigger update_version_column after update on host_plugin_version
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on host_plugin_version
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin_version
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin_version
    for each row execute procedure immutable_columns('public_id', 'plugin_id','create_time', 'version');

  insert into oplog_ticket (name, version)
  values
    ('host_plugin', 1),
    ('host_plugin_version', 1);

commit;
