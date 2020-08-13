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

  insert into oplog_ticket (name, version)
  values
    ('host_catalog', 1),
    ('host', 1),
    ('host_set', 1);

commit;
