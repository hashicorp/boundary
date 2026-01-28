-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- The 'comment on function' statements below are not for the functions in the
  -- file. They incorrectly override the comments for functions declared in
  -- 7/01_functions.up.sql. Fixes are contained in 58/01_fix_comments.up.sql.

    create function wt_sub_seconds(sec integer, ts timestamp with time zone) returns timestamp with time zone
    as $$
    select ts - sec * '1 second'::interval;
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds is
      'wt_sub_seconds returns ts - sec.';

    create function wt_sub_seconds_from_now(sec integer) returns timestamp with time zone
    as $$
    select wt_sub_seconds(sec, current_timestamp);
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds_to_now is
      'wt_sub_seconds_from_now returns current_timestamp - sec.';

commit;
