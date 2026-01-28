-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create function hst_table_name(table_schema name, operational_table_name name) returns text
  as $$
    select quote_ident(table_schema) || '.' || quote_ident(operational_table_name) || '_hst';
  $$ language sql
     immutable
     parallel safe -- all of the functions called are parallel safe
     cost 1        -- all of the functions called are cost 1
     strict;       -- means the function returns null on null input
  comment on function hst_table_name is
    'Returns the history table name of the operational table';

  create function hst_columns(table_schema name, operational_table_name name) returns setof text
  as $$
  declare
    _opr_tbl regclass := quote_ident(table_schema) || '.' || quote_ident(operational_table_name);
    _hst_tbl regclass := hst_table_name(table_schema, operational_table_name);
  begin
    return query
         select quote_ident(attname)
           from pg_attribute
          where attrelid = _opr_tbl
            and not attisdropped   -- no dropped (dead) columns
            and attnum > 0         -- no system columns
      intersect
         select quote_ident(attname)
           from pg_attribute
          where attrelid = _hst_tbl
            and not attisdropped   -- no dropped (dead) columns
            and attnum > 0;        -- no system columns
  end;
  $$ language plpgsql
     stable
     parallel safe -- all of the functions called are parallel safe
     -- cost ?     -- cost is unknown since it executes a query
     strict;       -- means the function returns null on null input
  comment on function hst_columns is
    'Returns the intersection of columns between an operational table and it''s history table. '
    'Raises an error if the operational table or history table do not exist.';

  create function hst_on_insert() returns trigger
  as $$
  declare
    _hst_tbl regclass := hst_table_name(tg_table_schema, tg_table_name);
    _cols text;
    _vals text;
  begin

    select into _cols, _vals
         string_agg(quote_ident(hst_columns), ', '), string_agg('x.' || quote_ident(hst_columns), ', ')
    from hst_columns(tg_table_schema, tg_table_name);

    execute format('
      insert into %s (%s)
      select %s
        from (select ($1).*) x', _hst_tbl, _cols, _vals)
    using new;

    return new;
  end;
  $$ language plpgsql;
  comment on function hst_on_insert is
    'hst_on_insert is an after insert trigger for any operational table that has a history table.';

  create function hst_on_delete() returns trigger
  as $$
  declare
    _hst_tbl regclass := hst_table_name(tg_table_schema, tg_table_name);
  begin

    execute format('
      update %s
         set valid_range = tstzrange(lower(valid_range), current_timestamp)
       where public_id = $1.public_id
         and valid_range @> current_timestamp', _hst_tbl)
    using old;

    return old;
  end;
  $$ language plpgsql;
  comment on function hst_on_delete is
    'hst_on_delete is an after delete trigger for any operational table that has a history table.';

  create function hst_on_update() returns trigger
  as $$
  declare
    _hst_tbl regclass := hst_table_name(tg_table_schema, tg_table_name);
    _cols text;
    _vals text;
    _new_values record;
    _old_values record;
  begin

    select into _cols, _vals
         string_agg(quote_ident(hst_columns), ', '), string_agg('x.' || quote_ident(hst_columns), ', ')
    from hst_columns(tg_table_schema, tg_table_name);

    execute format('select %s from (select ($1).*) x', _cols, _vals) into _new_values using new;
    execute format('select %s from (select ($1).*) x', _cols, _vals) into _old_values using old;
    if _new_values is distinct from _old_values then
    -- if one column has changed,
      -- same query as on_delete
      execute format('
        update %s
           set valid_range = tstzrange(lower(valid_range), current_timestamp)
         where public_id = $1.public_id
           and valid_range @> current_timestamp', _hst_tbl)
      using new;
      -- same query as on_insert
      execute format('
        insert into %s (%s)
        select %s
          from (select ($1).*) x', _hst_tbl, _cols, _vals)
      using new;
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function hst_on_update is
    'hst_on_update is an after update trigger for any operational table that has a history table.';

commit;
