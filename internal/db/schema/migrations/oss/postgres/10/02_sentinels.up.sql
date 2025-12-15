-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create function wt_is_sentinel(string text) returns bool
  as $$
    select length(trim(leading u&'\fffe ' from string)) > 0 AND starts_with(string, u&'\fffe');
  $$ language sql
     immutable
     returns null on null input;
  comment on function wt_is_sentinel is
    'wt_is_sentinel returns true if string is a sentinel value';

  create domain wt_sentinel as text
    constraint wt_sentinel_not_valid
      check(
        wt_is_sentinel(value)
        or
        length(trim(u&'\fffe ' from value)) > 0
      );
  comment on domain wt_sentinel is
    'A non-empty string with a Unicode prefix of U+FFFE to indicate it is a sentinel value';

  create function wt_to_sentinel(string text) returns text
  as $$
    select concat(u&'\fffe', trim(ltrim(string, u&'\fffe ')));
  $$ language sql
     immutable
     returns null on null input;
  comment on function wt_to_sentinel is
    'wt_to_sentinel takes string and returns it as a wt_sentinel';

commit;
