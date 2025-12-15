-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

/*

                               ┌─────────────────┐
                               │      host       │
                               ├─────────────────┤
                               │ public_id  (pk) │
                               │ catalog_id (fk) │
                               │                 │
                               └─────────────────┘
                                       ╲│╱
                                        ○
                                        │
                                        ┼
                                        ┼
  ┌─────────────────┐          ┌─────────────────┐
  │    iam_scope    │          │  host_catalog   │
  ├─────────────────┤          ├─────────────────┤
  │ public_id (pk)  │         ╱│ public_id (pk)  │
  │                 │┼┼──────○─│ scope_id  (fk)  │
  │                 │         ╲│                 │
  └─────────────────┘          └─────────────────┘
                                        ┼
                                        ┼
                                        │
                                        ○
                                       ╱│╲
                               ┌─────────────────┐
                               │    host_set     │
                               ├─────────────────┤
                               │ public_id  (pk) │
                               │ catalog_id (fk) │
                               │                 │
                               └─────────────────┘

*/

  -- host_catalog
  create table host_catalog (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      references iam_scope (public_id)
      on delete cascade
      on update cascade,

    -- The order of columns is important for performance. See:
    -- https://dba.stackexchange.com/questions/58970/enforcing-constraints-two-tables-away/58972#58972
    -- https://dba.stackexchange.com/questions/27481/is-a-composite-index-also-good-for-queries-on-the-first-field
    unique(scope_id, public_id)
  );

  create trigger immutable_columns before update on host_catalog
    for each row execute procedure immutable_columns('public_id', 'scope_id');

  -- insert_host_catalog_subtype() is a before insert trigger
  -- function for subtypes of host_catalog
  create or replace function insert_host_catalog_subtype() returns trigger
  as $$
  begin
    insert into host_catalog
      (public_id, scope_id)
    values
      (new.public_id, new.scope_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_host_catalog_subtype() is an after delete trigger
  -- function for subtypes of host_catalog
  create or replace function delete_host_catalog_subtype() returns trigger
  as $$
  begin
    delete from host_catalog
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  -- host
  create table host (
    public_id wt_public_id primary key,
    catalog_id wt_public_id not null
      references host_catalog (public_id)
      on delete cascade
      on update cascade,
    unique(catalog_id, public_id)
  );

  create trigger immutable_columns before update on host
    for each row execute procedure immutable_columns('public_id', 'catalog_id');

  -- insert_host_subtype() is a before insert trigger
  -- function for subtypes of host
  create or replace function insert_host_subtype() returns trigger
  as $$
  begin
    insert into host
      (public_id, catalog_id)
    values
      (new.public_id, new.catalog_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_host_subtype() is an after delete trigger
  -- function for subtypes of host
  create or replace function delete_host_subtype() returns trigger
  as $$
  begin
    delete from host
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  -- host_set
  create table host_set (
    public_id wt_public_id primary key,
    catalog_id wt_public_id not null
      references host_catalog (public_id)
      on delete cascade
      on update cascade,
    unique(catalog_id, public_id)
  );

  create trigger immutable_columns before update on host_set
    for each row execute procedure immutable_columns('public_id', 'catalog_id');

  -- insert_host_set_subtype() is a before insert trigger
  -- function for subtypes of host_set
  -- Replaced in 46/02_hosts.up.sql
  create or replace function insert_host_set_subtype() returns trigger
  as $$
  begin
    insert into host_set
      (public_id, catalog_id)
    values
      (new.public_id, new.catalog_id);
    return new;
  end;
  $$ language plpgsql;

  -- delete_host_set_subtype() is an after delete trigger
  -- function for subtypes of host_set
  create or replace function delete_host_set_subtype() returns trigger
  as $$
  begin
    delete from host_set
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;

  insert into oplog_ticket (name, version)
  values
    ('host_catalog', 1),
    ('host', 1),
    ('host_set', 1);

commit;
