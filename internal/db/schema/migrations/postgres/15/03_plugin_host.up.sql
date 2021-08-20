begin;

/*
                             ┌──────────────────┐
                             │   host_plugin    │
                             ├──────────────────┤
                             │public_id (pk)    │
                             │...               │
                             └──────────────────┘
                                       ┼
                                       ┼
                                       ○
                                      ╱│╲
                            ┌─────────────────────┐
                            │ plugin_host_catalog │
                            ├─────────────────────┤      ┌───────────────────────────┐
    ┌────────────────┐      │public_id (pk)       │      │plugin_host_catalog_secrets│
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
    ┌────────────────┐      │  plugin_host_set   │
    │    host_set    │      ├────────────────────┤
    ├────────────────┤      │public_id (pk)      │
    │public_id       │      │host_catalog_id (fk)│
    │host_catalog_id │┼┼──○┼│name                │
    └────────────────┘      │description         │
                            │attributes          │
                            └────────────────────┘

*/

  create table plugin_host_catalog (
    public_id wt_public_id
      primary key,
    scope_id wt_scope_id
      not null
      references iam_scope (public_id)
      on delete cascade
      on update cascade,
    plugin_id wt_scope_id
      not null
      references host_plugin (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    attributes bytea,
    foreign key (scope_id, public_id)
      references host_catalog (scope_id, public_id)
      on delete cascade
      on update cascade,
    unique(scope_id, name)
  );

  create trigger update_version_column after update on plugin_host_catalog
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on plugin_host_catalog
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on plugin_host_catalog
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on plugin_host_catalog
    for each row execute procedure immutable_columns('public_id', 'scope_id','create_time');

  create trigger insert_host_catalog_subtype before insert on plugin_host_catalog
    for each row execute procedure insert_host_catalog_subtype();

  create trigger update_host_catalog_subtype before update on plugin_host_catalog
    for each row execute procedure update_host_catalog_subtype();

  create trigger delete_host_catalog_subtype after delete on plugin_host_catalog
    for each row execute procedure delete_host_catalog_subtype();

  create table plugin_host_catalog_secret (
    catalog_id wt_public_id primary key
      references plugin_host_catalog (public_id)
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

  create trigger update_time_column before update on plugin_host_catalog_secret
      for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on plugin_host_catalog_secret
      for each row execute procedure default_create_time();

  create trigger immutable_columns before update on plugin_host_catalog_secret
      for each row execute procedure immutable_columns('catalog_id', 'create_time');

  create table plugin_host_set (
    public_id wt_public_id primary key,
    catalog_id wt_public_id not null
      references plugin_host_catalog (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    attributes bytea,
    unique(catalog_id, name),
    foreign key (catalog_id, public_id)
      references host_set (catalog_id, public_id)
      on delete cascade
      on update cascade,
    unique(catalog_id, public_id)
  );

  create trigger update_version_column after update on plugin_host_set
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on plugin_host_set
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on plugin_host_set
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on plugin_host_set
    for each row execute procedure immutable_columns('public_id', 'catalog_id','create_time');

  create trigger insert_host_set_subtype before insert on plugin_host_set
    for each row execute procedure insert_host_set_subtype();

  create trigger delete_host_set_subtype after delete on plugin_host_set
    for each row execute procedure delete_host_set_subtype();

  insert into oplog_ticket (name, version)
  values
    ('plugin_host_catalog', 1),
    ('plugin_host_catalog_secret', 1),
    ('plugin_host_set', 1);

commit;
