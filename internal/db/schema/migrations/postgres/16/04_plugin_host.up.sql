begin;

/*
                             ┌──────────────────┐
                             │   plugin_host    │
                             ├──────────────────┤
                             │public_id (pk)    │
                             │...               │
                             └──────────────────┘
                                       ┼
                                       ┼
                                       ○
                                      ╱│╲
                            ┌─────────────────────┐
                            │ host_plugin_catalog │
                            ├─────────────────────┤      ┌───────────────────────────┐
    ┌────────────────┐      │public_id (pk)       │      │host_plugin_catalog_secret │
    │host_catalog    │      │plugin_id (fk)       │      ├───────────────────────────┤
    ├────────────────┤      │scope_id (fk)        │      │host_catalog_id (pk, fk)   │
    │public_id       │┼┼──○┼│name                 │┼┼──○┼│secret                     │
    │scope_id        │      │description          │      │key_id (fk)                │
    └────────────────┘      │attributes           │      └───────────────────────────┘
             ┼              └─────────────────────┘
             ┼                         ┼
             │                         ┼
             │                         ○
             ○                        ╱│╲
            ╱│╲             ┌────────────────────┐
    ┌────────────────┐      │  host_plugin_set   │
    │    host_set    │      ├────────────────────┤
    ├────────────────┤      │public_id (pk)      │
    │public_id       │      │host_catalog_id (fk)│
    │host_catalog_id │┼┼──○┼│name                │
    └────────────────┘      │description         │
                            │attributes          │
                            └────────────────────┘

*/

  create table host_plugin_catalog (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint scope_fkey
        references iam_scope (public_id)
        on delete cascade
        on update cascade,
    plugin_id wt_plugin_id not null
      constraint plugin_host_fkey
        references plugin_host (public_id)
        on delete cascade
        on update cascade,
    name wt_name,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    attributes bytea not null,
    constraint host_catalog_fkey
    foreign key (scope_id, public_id)
      references host_catalog (scope_id, public_id)
      on delete cascade
      on update cascade,
    constraint catalog_name_must_be_unique_in_scope
    unique(scope_id, name)
  );

  create trigger update_version_column after update on host_plugin_catalog
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on host_plugin_catalog
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin_catalog
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin_catalog
    for each row execute procedure immutable_columns('public_id', 'scope_id', 'plugin_id', 'create_time');

  create trigger insert_host_catalog_subtype before insert on host_plugin_catalog
    for each row execute procedure insert_host_catalog_subtype();

  create trigger update_host_catalog_subtype before update on host_plugin_catalog
    for each row execute procedure update_host_catalog_subtype();

  create trigger delete_host_catalog_subtype after delete on host_plugin_catalog
    for each row execute procedure delete_host_catalog_subtype();

  create table host_plugin_catalog_secret (
    catalog_id wt_public_id primary key
      constraint host_plugin_catalog_fkey
      references host_plugin_catalog (public_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    secret bytea not null  -- encrypted value
      constraint secret_must_not_be_empty
        check(length(secret) > 0),
    key_id wt_private_id not null
      constraint kms_database_key_version_fkey
        references kms_database_key_version (private_id)
        on delete restrict
        on update cascade
  );

  create trigger update_time_column before update on host_plugin_catalog_secret
      for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin_catalog_secret
      for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin_catalog_secret
      for each row execute procedure immutable_columns('catalog_id', 'create_time');

  create table host_plugin_set (
    public_id wt_public_id primary key,
    catalog_id wt_public_id not null
      constraint host_plugin_catalog_fkey
        references host_plugin_catalog (public_id)
        on delete cascade
        on update cascade,
    name wt_name,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    attributes bytea not null,
    constraint host_plugin_set_name_must_be_unique_in_catalog
    unique(catalog_id, name),
    constraint host_set_fkey
    foreign key (catalog_id, public_id)
      references host_set (catalog_id, public_id)
      on delete cascade
      on update cascade,
    constraint public_id_is_unique_in_catalog
    unique(catalog_id, public_id)
  );

  create trigger update_version_column after update on host_plugin_set
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on host_plugin_set
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin_set
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin_set
    for each row execute procedure immutable_columns('public_id', 'catalog_id','create_time');

  create trigger insert_host_set_subtype before insert on host_plugin_set
    for each row execute procedure insert_host_set_subtype();

  create trigger delete_host_set_subtype after delete on host_plugin_set
    for each row execute procedure delete_host_set_subtype();

  insert into oplog_ticket (name, version)
  values
    ('host_plugin_catalog', 1),
    ('host_plugin_catalog_secret', 1),
    ('host_plugin_set', 1);

commit;
