-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
-- Session list queries always use an order by on create_time.
-- This index can aide in performing this order by.
create index
  session_create_time
on
  session (create_time);

analyze session;

commit;
