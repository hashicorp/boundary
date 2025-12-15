-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

/*
  ┌──────────────────┐
  │      plugin      │
  ├──────────────────┤
  │public_id (pk)    │
  │scope_id (fk)     │
  │name              │
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
  └──────────────────┘
*/
  create table plugin_host (
    public_id wt_plugin_id primary key,
    scope_id wt_scope_id not null
    constraint iam_scope_global_fkey
      references iam_scope_global(scope_id)
      on delete cascade
      on update cascade,
    name wt_name,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    constraint plugin_fkey
    foreign key (scope_id, public_id)
      references plugin(scope_id, public_id)
      on delete cascade
      on update cascade,
    constraint plugin_host_scope_id_name_uq
    unique(scope_id, name)
  );

  create trigger update_version_column after update on plugin_host
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on plugin_host
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on plugin_host
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on plugin_host
    for each row execute procedure immutable_columns('public_id', 'create_time');

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
