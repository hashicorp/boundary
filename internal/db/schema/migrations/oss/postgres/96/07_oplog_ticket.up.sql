-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
insert into oplog_ticket
             (name, version)
     values  ('iam_role_global',1),
             ('iam_role_org', 1),
             ('iam_role_project', 1);
commit;