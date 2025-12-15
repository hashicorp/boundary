-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table census_last_uploaded (
    last_uploaded_at wt_timestamp primary key
  );
  comment on table census_last_uploaded is
    'census_last_uploaded is a table with 1 row which contains '
    'the timestamp of the last time census data was uploaded.';

  -- This index ensures that there will only ever be one row in the table.
  -- See: https://www.postgresql.org/docs/current/indexes-expressional.html
  -- Dropped in 82/09_census_add_metric.up.sql
  create unique index census_last_uploaded_one_row
    on census_last_uploaded((last_uploaded_at is not null));

  insert into census_last_uploaded(last_uploaded_at) values('-infinity');

commit;
