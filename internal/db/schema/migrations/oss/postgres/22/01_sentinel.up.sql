-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create function wt_to_sentinel(string text) returns text
  as $$
    select concat(
      u&'\fffe',
      trim(trailing u&'\ffff' from trim(leading u&'\fffe ' from string)),
      u&'\ffff'
    );
  $$ language sql
     immutable
     returns null on null input;
  comment on function wt_to_sentinel is
    'wt_to_sentinel takes a string and returns it as a wt_sentinel';

commit;
