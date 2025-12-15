-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

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
      constraint iam_scope_fkey
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
    constraint host_plugin_catalog_scope_id_name_uq
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
    last_sync_time wt_timestamp,
    need_sync bool not null,
    sync_interval_seconds int
      constraint sync_interval_seconds_not_equal_zero
        check(sync_interval_seconds != 0)
      constraint sync_interval_seconds_not_less_then_negative_one
        check(sync_interval_seconds >= -1),
    version wt_version,
    attributes bytea not null,
    constraint host_plugin_set_catalog_id_name_uq
    unique(catalog_id, name),
    constraint host_set_fkey
      foreign key (catalog_id, public_id)
        references host_set (catalog_id, public_id)
        on delete cascade
        on update cascade,
    constraint host_plugin_set_catalog_id_public_id_uq
    unique(catalog_id, public_id)
  );

  create trigger update_version_column after update on host_plugin_set
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on host_plugin_set
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin_set
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin_set
    for each row execute procedure immutable_columns('public_id', 'catalog_id', 'create_time');

  create trigger insert_host_set_subtype before insert on host_plugin_set
    for each row execute procedure insert_host_set_subtype();

  create trigger delete_host_set_subtype after delete on host_plugin_set
    for each row execute procedure delete_host_set_subtype();

-- host_plugin_host captures plugin based host data.  This is only written to
  -- from the controller and is not mutable directly by actions from the end
  -- user.
  create table host_plugin_host (
    public_id wt_public_id primary key,
    catalog_id wt_public_id not null
      constraint host_plugin_catalog_fkey
        references host_plugin_catalog (public_id)
        on delete cascade
        on update cascade,
    external_id text not null
      constraint external_id_must_not_be_empty
        check(length(trim(external_id)) > 0),
    name wt_name,
    description text,
    create_time wt_timestamp,
    -- update_time is the last time the data was synced with what is provided
    -- from the plugin.
    update_time wt_timestamp,
    constraint host_fkey
      foreign key (catalog_id, public_id)
        references host (catalog_id, public_id)
        on delete cascade
        on update cascade,
    constraint host_plugin_host_catalog_id_external_id_uq
      unique(catalog_id, external_id),
    constraint host_plugin_host_catalog_id_public_id_uq
      unique(catalog_id, public_id)
  );

  create trigger update_time_column before update on host_plugin_host
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on host_plugin_host
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin_host
    for each row execute procedure immutable_columns('public_id', 'catalog_id', 'external_id', 'create_time');

  -- insert_host_plugin_host_subtype is intended as a before insert trigger on
  -- host_plugin_host. Its purpose is to insert a base host for new plugin-based
  -- hosts. It's a bit different than the standard trigger for this, because it
  -- will have conflicting PKs and we just want to "do nothing" on those
  -- conflicts, deferring the raising on an error to insert into the
  -- host_plugin_host table. This allows the upsert-style workflow.
  create or replace function insert_host_plugin_host_subtype() returns trigger
  as $$
  begin
    insert into host
      (public_id, catalog_id)
    values
      (new.public_id, new.catalog_id)
    on conflict do nothing;

    return new;
  end;
    $$ language plpgsql;

  create trigger insert_host_plugin_host_subtype before insert on host_plugin_host
    for each row execute procedure insert_host_plugin_host_subtype();

  create trigger delete_host_subtype after delete on host_plugin_host
    for each row execute procedure delete_host_subtype();

  -- host_ip_address contains the IP addresses associated with
  -- a host, one per row.
  create table host_ip_address (
    host_id wt_public_id
      constraint host_fkey
        references host(public_id)
        on delete cascade
        on update cascade,
    address inet not null,
    create_time wt_timestamp,
    primary key (host_id, address)
  );
  comment on table host_ip_address is
    'host_ip_address entries are ip addresses set on a host.';

  create trigger default_create_time_column before insert on host_ip_address
    for each row execute procedure default_create_time();

  -- host_immutable_ip_address() ensures that ip addresses assigned to hosts are
  -- immutable.
  create function host_immutable_ip_address() returns trigger
  as $$
  begin
    raise exception 'host ip addresses are immutable';
  end;
  $$ language plpgsql;
  
  create trigger immutable_ip_address before update on host_ip_address
    for each row execute procedure host_immutable_ip_address();

  -- host_dns_name contains the DNS names associated with a host, one per row.
  create table host_dns_name (
    host_id wt_public_id
      constraint host_fkey
        references host(public_id)
        on delete cascade
        on update cascade,
    name wt_dns_name,
    create_time wt_timestamp,
    primary key (host_id, name)
  );
  comment on table host_dns_name is
    'host_dns_name entries are dns names set on a host';

  create trigger default_create_time_column before insert on host_dns_name
    for each row execute procedure default_create_time();

  -- host_immutable_dns_name() ensures that dns names assigned to hosts are
  -- immutable.
  create function host_immutable_dns_name() returns trigger
  as $$
  begin
    raise exception 'host dns names are immutable';
  end;
  $$ language plpgsql;

  create trigger immutable_dns_name before update on host_dns_name
    for each row execute procedure host_immutable_dns_name();

  create table host_plugin_set_member (
    host_id wt_public_id not null,
    set_id wt_public_id not null,
    catalog_id wt_public_id not null,
    create_time wt_timestamp,
    primary key(host_id, set_id),
    constraint host_plugin_host_fkey
      foreign key (catalog_id, host_id)
        references host_plugin_host (catalog_id, public_id)
        on delete cascade
        on update cascade,
    constraint host_plugin_set_fkey
      foreign key (catalog_id, set_id)
        references host_plugin_set (catalog_id, public_id)
        on delete cascade
        on update cascade
  );
  comment on table host_plugin_set_member is
    'host_plugin_set_member entries are the membership relationships from plugin hosts in plugin sets.';

  create trigger default_create_time_column before insert on host_plugin_set_member
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on host_plugin_set_member
    for each row execute procedure immutable_columns('host_id', 'set_id', 'catalog_id', 'create_time');

  create function insert_host_plugin_set_member() returns trigger
  as $$
  begin
    select host_plugin_set.catalog_id
      into new.catalog_id
    from host_plugin_set
    where host_plugin_set.public_id = new.set_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_host_plugin_set_member is
    'insert_host_plugin_set_member entries are the membership relationships from plugin hosts in plugin sets.';

  create trigger insert_host_plugin_set_member before insert on host_plugin_set_member
    for each row execute procedure insert_host_plugin_set_member();

  create table host_set_preferred_endpoint (
    create_time wt_timestamp,
    host_set_id wt_public_id not null
      constraint host_set_fkey
        references host_set(public_id)
        on delete cascade
        on update cascade,
    priority wt_priority,
    condition text not null
      constraint condition_must_not_be_too_short
        check(length(trim(condition)) > 4) -- minimum is 'dns:*'
      constraint condition_must_not_be_too_long
        check(length(trim(condition)) < 255)
      constraint condition_has_valid_prefix
        check(
              left(trim(condition), 4) = 'dns:'
            or
              left(trim(condition), 5) = 'cidr:'
          )
      constraint condition_does_not_contain_invalid_chars
        check(
              position('|' in trim(condition)) = 0
            and
              position('=' in trim(condition)) = 0
          ),
    primary key(host_set_id, priority),
    constraint host_set_preferred_endpoint_host_set_id_condition_uq
      unique(host_set_id, condition)
  );

  -- host_set_immutable_preferred_endpoint() ensures that endpoint conditions
  -- assigned to host sets are immutable.
  create function host_set_immutable_preferred_endpoint() returns trigger
  as $$
  begin
    raise exception 'preferred endpoints are immutable';
  end;
  $$ language plpgsql;

  create trigger immutable_preferred_endpoint before update on host_set_preferred_endpoint
    for each row execute procedure host_set_immutable_preferred_endpoint();

  insert into oplog_ticket (name, version)
  values
    ('host_plugin_catalog', 1),
    ('host_plugin_set', 1),
    ('host_plugin_host', 1);

commit;
