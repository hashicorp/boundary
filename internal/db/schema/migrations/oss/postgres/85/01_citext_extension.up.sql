-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- https://www.postgresql.org/docs/14/citext.html allows us to make
  -- case-insensitive uniqueness constraints which is useful to us for
  -- aliases.
  create extension "citext";

commit;
