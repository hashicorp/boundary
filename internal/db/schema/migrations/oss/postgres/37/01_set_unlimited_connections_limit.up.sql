-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Changes the default that was set in 0/41_targets.up.sql
alter table target_tcp
    alter column session_connection_limit set default -1;

commit;
