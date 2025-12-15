-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(6);

  -- Verify the function exists and is declared properly
  select has_function('hst_columns', array['name', 'name']);
  select volatility_is('hst_columns', 'stable');
  select is_strict('hst_columns');

  select is(count(*), 0::bigint, 'null input should return 0 rows') from hst_columns(null, null);

  -- close to the iam_user table
  create table test_r1 (
    public_id wt_user_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_scope_id not null
      references iam_scope(public_id)
      on delete cascade
      on update cascade,
    unique(name, scope_id),
    version wt_version
  );

  create table test_r1_hst (
    public_id wt_user_id not null,
    name text,
    description text,
    scope_id text not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key,
    valid_range tstzrange not null default tstzrange(current_timestamp, null)
  );

  select is(count(*), 4::bigint) from hst_columns('public'::name, 'test_r1'::name);

  create table test_r2 (
    public_id wt_user_id primary key,
    create_time wt_timestamp,
    update_time wt_timestamp,
    name text,
    description text,
    scope_id wt_scope_id not null
      references iam_scope(public_id)
      on delete cascade
      on update cascade,
    version wt_version
  );

  prepare select_no_history_table as select hst_columns('public'::name, 'test_r2'::name);
  select throws_like('select_no_history_table', '%relation "public.test_r2_hst" does not exist', 'an operational table without a history table should raise an error');

  select * from finish();
rollback;
