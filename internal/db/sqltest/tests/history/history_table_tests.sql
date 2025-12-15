-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create function get_columns(history_table_name name) returns setof text
  as $$
  begin
    return query
         select quote_ident(attname)
           from pg_attribute
          where attrelid = op_table(history_table_name)::regclass
            and not attisdropped   -- no dropped (dead) columns
            and attnum > 0         -- no system columns
      intersect
         select quote_ident(attname)
           from pg_attribute
          where attrelid = history_table_name::regclass
            and not attisdropped   -- no dropped (dead) columns
            and attnum > 0;        -- no system columns
  end;
  $$ language plpgsql;

  create function get_history_tables() returns setof name
  as $$
    select c.relname
      from pg_catalog.pg_class c
     where c.relkind in ('r')
       and c.relname operator(pg_catalog.~) '^(.*hst)$' collate pg_catalog.default
       and pg_catalog.pg_table_is_visible(c.oid);
  $$ language sql;

  create function op_table(history_table_name name) returns text
  as $$
    select left(history_table_name, -4);
  $$ language sql;

  create function has_operational_table(history_table_name name) returns text
  as $$
    select has_table(op_table(history_table_name));
  $$ language sql;

  create function get_col_type(table_name name, column_name name) returns text
  as $$
    select pg_catalog.format_type(a.atttypid, a.atttypmod)
      from pg_catalog.pg_attribute a
      join pg_catalog.pg_class c on a.attrelid = c.oid
     where pg_catalog.pg_table_is_visible(c.oid)
       and c.relname = table_name
       and a.attname = column_name
       and attnum > 0
       and not a.attisdropped;
  $$ language sql;

  create function col_types_equal(history_table_name name, column_name name) returns text
  as $$
  declare
    want_type text;
  begin
    want_type := get_col_type(op_table(history_table_name), column_name);
    return col_type_is(history_table_name, column_name, want_type);
  end;
  $$ language plpgsql;

  create function has_expected_row_count(history_table_name name) returns text
  as $$
  declare
    result text;
  begin
    execute format('select results_eq( '
        ' ''select count(*) from %I'', '
        ' ''select count(*) from %I'', '
        ' ''%I failed has_expected_row_count'') ',
        op_table(history_table_name), history_table_name, history_table_name)
    into result;
    return result;
  end;
  $$ language plpgsql;

  create function has_expected_content(history_table_name name) returns text
  as $$
  declare
    _cols text;
    _q1 text;
    _q2 text;
  begin
    select into _cols
         string_agg(quote_ident(get_columns), ', ')
    from get_columns(history_table_name);
    select into _q1 format('select %s from %s', _cols, history_table_name);
    select into _q2 format('select %s from %s', _cols, op_table(history_table_name));
    return results_eq(_q1, _q2, history_table_name || ' failed has_expected_content');

  end;
  $$ language plpgsql;

  create function has_expected_data(history_table_name name) returns text
  as $$
    select * from collect_tap(
      has_expected_row_count(history_table_name),
      has_expected_content(history_table_name)
    );
  $$ language sql;

  -- tests the tables exist and follow the required naming pattern
  create function has_correct_tables(history_table_name name) returns text
  as $$
    select * from collect_tap(
      has_table(history_table_name),
      has_operational_table(history_table_name),
      has_expected_data(history_table_name)
    );
  $$ language sql;

  -- tests the public_id column
  create function has_public_id(history_table_name name) returns text
  as $$
    select * from collect_tap(
      has_column(history_table_name, 'public_id'),
      col_not_null(history_table_name, 'public_id'),
      col_types_equal(history_table_name, 'public_id'), -- should be the same type as the operational table
      col_hasnt_default(history_table_name, 'public_id')
    );
  $$ language sql;

  -- tests the history_id column
  create function has_history_id(history_table_name name) returns text
  as $$
    select * from collect_tap(
      has_column(history_table_name, 'history_id'),
      col_is_pk(history_table_name, 'history_id'),
      col_type_is(history_table_name, 'history_id', 'wt_url_safe_id'),
      col_has_default(history_table_name, 'history_id'),
      col_default_is(history_table_name, 'history_id', 'wt_url_safe_id()')
    );
  $$ language sql;

  -- tests the valid_range column
  create function has_valid_range(history_table_name name) returns text
  as $$
    select * from collect_tap(
      has_column(history_table_name, 'valid_range'),
      col_not_null(history_table_name, 'valid_range'),
      col_type_is(history_table_name, 'valid_range', 'tstzrange'),
      col_has_default(history_table_name, 'valid_range'),
      col_default_is(history_table_name, 'valid_range', 'tstzrange(CURRENT_TIMESTAMP, NULL::timestamp with time zone)')
    );
  $$ language sql;

  -- tests for an exclusion index
  create function has_exclusion_index(history_table_name name) returns text
  as $$
    select case when length(history_table_name || '_valid_range_excl') > 63
           then hasnt_index(history_table_name, history_table_name || '_valid_range_excl', 'Index name too long: ' || history_table_name || '_valid_range_excl')
           else collect_tap(
                has_index(history_table_name, history_table_name || '_valid_range_excl', array['public_id', 'valid_range'])
              ) end;
  $$ language sql;

  -- tests to verify certain columns are not in the history table
  create function hasnt_operational_columns(history_table_name name) returns text
  as $$
    select * from collect_tap(
      hasnt_column(history_table_name, 'create_time'),
      hasnt_column(history_table_name, 'update_time'),
      hasnt_column(history_table_name, 'version')
    );
  $$ language sql;

  -- tests that the operational table has the history triggers
  create function has_history_triggers(history_table_name name) returns text
  as $$
    select * from collect_tap(
      has_trigger(op_table(history_table_name), 'hst_on_insert'),
      trigger_is(op_table(history_table_name), 'hst_on_insert', 'hst_on_insert'),
      has_trigger(op_table(history_table_name), 'hst_on_update'),
      trigger_is(op_table(history_table_name), 'hst_on_update', 'hst_on_update'),
      has_trigger(op_table(history_table_name), 'hst_on_delete'),
      trigger_is(op_table(history_table_name), 'hst_on_delete', 'hst_on_delete')
    );
  $$ language sql;

  -- runs all the tests on a single history table
  create function test_history_table(history_table_name name) returns text
  as $$
    select * from collect_tap(
      has_correct_tables(history_table_name),
      has_public_id(history_table_name),
      has_history_id(history_table_name),
      has_valid_range(history_table_name),
      has_exclusion_index(history_table_name),
      hasnt_operational_columns(history_table_name),
      has_history_triggers(history_table_name)
    );
  $$ language sql;

  -- 28 tests for each history table
  select plan(a.table_count::integer)
    from (
      select 28 * count(*) as table_count
        from get_history_tables()
    ) as a;

    select test_history_table(a)
      from get_history_tables() a;

  select * from finish();
rollback;
