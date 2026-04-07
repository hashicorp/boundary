-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create domain tt_public_id as text
  check(
    length(trim(value)) > 10
  );
commit;
