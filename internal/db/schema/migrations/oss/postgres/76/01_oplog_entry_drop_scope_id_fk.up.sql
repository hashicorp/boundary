-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table oplog_entry
    drop constraint iam_scope_fkey;

commit;