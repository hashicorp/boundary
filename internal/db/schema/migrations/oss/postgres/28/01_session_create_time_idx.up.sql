-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
-- Session list queries always use an order by on create_time.
-- This index can aide in performing this order by.
-- Dropped in 81/05_session_base_table_updates.up.sql.
create index
  session_create_time
on
  session (create_time);

analyze session;

commit;
