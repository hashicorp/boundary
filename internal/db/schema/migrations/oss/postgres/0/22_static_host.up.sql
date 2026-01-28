-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

/*

  ┌─────────────────┐          ┌─────────────────────┐
  │      host       │          │     static_host     │
  ├─────────────────┤          ├─────────────────────┤
  │ public_id  (pk) │          │ public_id  (pk)     │
  │ catalog_id (fk) │┼┼──────○┼│ catalog_id (fk)     │┼┼─────────────────────┐
  │                 │          │ address             │             ◀fk1      │
  └─────────────────┘          └─────────────────────┘                       │
          ╲│╱                            ╲│╱                                 │
           ○                              ○                                  │
           │                              │                                  │
           ┼                              ┼                                  ○
           ┼                              ┼                                 ╱│╲
  ┌─────────────────┐          ┌─────────────────────┐          ┌────────────────────────┐
  │  host_catalog   │          │ static_host_catalog │          │ static_host_set_member │
  ├─────────────────┤          ├─────────────────────┤          ├────────────────────────┤
  │ public_id (pk)  │          │ public_id (pk)      │          │ host_id    (pk,fk1)    │
  │ scope_id  (fk)  │┼┼──────○┼│ scope_id  (fk)      │          │ set_id     (pk,fk2)    │
  │                 │          │                     │          │ catalog_id (fk1,fk2)   │
  └─────────────────┘          └─────────────────────┘          └────────────────────────┘
           ┼                              ┼                                 ╲│╱
           ┼                              ┼                                  ○
           │                              │                                  │
           ○                              ○                                  │
          ╱│╲                            ╱│╲                                 │
  ┌─────────────────┐          ┌─────────────────────┐                       │
  │    host_set     │          │   static_host_set   │                       │
  ├─────────────────┤          ├─────────────────────┤                       │
  │ public_id  (pk) │          │ public_id  (pk)     │             ◀fk2      │
  │ catalog_id (fk) │┼┼──────○┼│ catalog_id (fk)     │┼┼─────────────────────┘
  │                 │          │                     │
  └─────────────────┘          └─────────────────────┘

*/

  create table static_host_catalog (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      references iam_scope (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    foreign key (scope_id, public_id)
      references host_catalog (scope_id, public_id)
      on delete cascade
      on update cascade,
    unique(scope_id, name)
  );

  create trigger update_version_column after update on static_host_catalog
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on static_host_catalog
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on static_host_catalog
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on static_host_catalog
    for each row execute procedure immutable_columns('public_id', 'scope_id','create_time');

  create trigger insert_host_catalog_subtype before insert on static_host_catalog
    for each row execute procedure insert_host_catalog_subtype();

  create trigger delete_host_catalog_subtype after delete on static_host_catalog
    for each row execute procedure delete_host_catalog_subtype();

  create table static_host (
    public_id wt_public_id primary key,
    catalog_id wt_public_id not null
      references static_host_catalog (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    address text not null
      constraint address_must_be_more_than_2_characters
      check(length(trim(address)) > 2)
      constraint address_must_be_less_than_256_characters
      check(length(trim(address)) < 256),
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    unique(catalog_id, name),

    foreign key (catalog_id, public_id)
      references host (catalog_id, public_id)
      on delete cascade
      on update cascade,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(catalog_id, public_id)
  );

  create trigger update_version_column after update on static_host
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on static_host
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on static_host
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on static_host
    for each row execute procedure immutable_columns('public_id', 'catalog_id','create_time');

  create trigger insert_host_subtype before insert on static_host
    for each row execute procedure insert_host_subtype();

  create trigger delete_host_subtype after delete on static_host
    for each row execute procedure delete_host_subtype();

  create table static_host_set (
    public_id wt_public_id primary key,
    catalog_id wt_public_id not null
      references static_host_catalog (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    unique(catalog_id, name),
    foreign key (catalog_id, public_id)
      references host_set (catalog_id, public_id)
      on delete cascade
      on update cascade,
    unique(catalog_id, public_id)
  );

  create trigger update_version_column after update on static_host_set
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on static_host_set
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on static_host_set
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on static_host_set
    for each row execute procedure immutable_columns('public_id', 'catalog_id','create_time');

  create trigger insert_host_set_subtype before insert on static_host_set
    for each row execute procedure insert_host_set_subtype();

  create trigger delete_host_set_subtype after delete on static_host_set
    for each row execute procedure delete_host_set_subtype();

  create table static_host_set_member (
    host_id wt_public_id not null,
    set_id wt_public_id not null,
    catalog_id wt_public_id not null,
    primary key(host_id, set_id),
    foreign key (catalog_id, host_id) -- fk1
      references static_host (catalog_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (catalog_id, set_id) -- fk2
      references static_host_set (catalog_id, public_id)
      on delete cascade
      on update cascade
  );

  create trigger immutable_columns before update on static_host_set_member
    for each row execute procedure immutable_columns('host_id', 'set_id', 'catalog_id');

  create or replace function insert_static_host_set_member() returns trigger
  as $$
  begin
    select static_host_set.catalog_id
      into new.catalog_id
    from static_host_set
    where static_host_set.public_id = new.set_id;
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_static_host_set_member before insert on static_host_set_member
    for each row execute procedure insert_static_host_set_member();

  insert into oplog_ticket (name, version)
  values
    ('static_host_catalog', 1),
    ('static_host', 1),
    ('static_host_set', 1),
    ('static_host_set_member', 1);

commit;
