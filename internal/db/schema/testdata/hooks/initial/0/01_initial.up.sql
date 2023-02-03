-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  create domain tt_public_id as text
  check(
    length(trim(value)) > 10
  );
commit;
