-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  insert into oplog_ticket (name, version)
  values
    ('app_token', 1);

commit;
