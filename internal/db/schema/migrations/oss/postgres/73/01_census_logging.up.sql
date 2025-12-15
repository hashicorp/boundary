-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table census_last_logged (
    last_logged_at wt_timestamp primary key
  );
  comment on table census_last_logged is
    'census_last_logged is a table with 1 row which contains the timestamp '
    'of the last time the census status and snapshots were logged.';

  -- This index ensures that there will only ever be one row in the table.
  -- See: https://www.postgresql.org/docs/current/indexes-expressional.html
  create unique index census_last_logged_one_row
    on census_last_logged((last_logged_at is not null));

  insert into census_last_logged(last_logged_at) values('-infinity');

commit;
