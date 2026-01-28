-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Comments for the functions below were incorrectly overridden in
  -- 12/01_timestamp_sub_funcs.up.sql but fixed in 58/01_fix_comments.up.sql.

    create function wt_add_seconds(sec integer, ts timestamp with time zone) returns timestamp with time zone
    as $$
    select ts + sec * '1 second'::interval;
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds is
      'wt_add_seconds returns ts + sec.';

    create function wt_add_seconds_to_now(sec integer) returns timestamp with time zone
    as $$
    select wt_add_seconds(sec, current_timestamp);
    $$ language sql
        stable
        returns null on null input;
    comment on function wt_add_seconds_to_now is
      'wt_add_seconds_to_now returns current_timestamp + sec.';

commit;
