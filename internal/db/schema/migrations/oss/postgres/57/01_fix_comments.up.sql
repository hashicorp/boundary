begin;

  -- Restores the correct comments originally defined in 7/01_functions.up.sql
  -- but incorrectly overridden in 12/01_timestamp_sub_funcs.up.sql.
  comment on function wt_add_seconds is 'wt_add_seconds returns ts + sec.';
  comment on function wt_add_seconds_to_now is 'wt_add_seconds_to_now returns current_timestamp + sec.';

  -- Sets comments for functions defined in 12/01_timestamp_sub_funcs.up.sql.
  comment on function wt_sub_seconds is 'wt_sub_seconds returns ts - sec.';
  comment on function wt_sub_seconds_from_now is 'wt_sub_seconds_from_now returns current_timestamp - sec.';

commit;
