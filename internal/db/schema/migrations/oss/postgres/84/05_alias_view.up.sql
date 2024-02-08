-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- alias_all_subtypes defines a view that retrieves the common columns from the
  -- subtype alias tables.
  create view alias_all_subtypes as
    select
      public_id,
      value,
      destination_id
    from alias_target;

commit;