-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- alias_view defines a view that retrieves the common columns from the
  -- subtype alias tables.
  create view alias_view as
    select
      public_id,
      value,
      destination_id
    from alias_target;

commit;