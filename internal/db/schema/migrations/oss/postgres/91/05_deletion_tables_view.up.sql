-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- Originially added in 81/01_deleted_tables_and_triggers.up.sql
  -- This is being replaced with a view.
  drop function get_deletion_tables;

  -- This view uses the pg_catalog to find all tables that end in _deleted and are visibile.
  -- See: https://www.postgresql.org/docs/current/catalog-pg-class.html
  --      https://www.postgresql.org/docs/current/functions-info.html#FUNCTIONS-INFO-SCHEMA
  create view deletion_table as
    select c.relname as tablename
      from pg_catalog.pg_class c
     where c.relkind in ('r') -- r = ordinary table
       and c.relname operator(pg_catalog.~) '^(.+_deleted)$' collate pg_catalog.default
       and pg_catalog.pg_table_is_visible(c.oid);
commit;
