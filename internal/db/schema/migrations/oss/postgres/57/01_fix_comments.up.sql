begin;

  -- Restores the correct comments originally defined in 7/01_functions.up.sql
  -- but incorrectly overridden in 12/01_timestamp_sub_funcs.up.sql.
  comment on function wt_add_seconds is 'wt_add_seconds returns ts + sec.';
  comment on function wt_add_seconds_to_now is 'wt_add_seconds_to_now returns current_timestamp + sec.';

  -- Sets comments for functions defined in 12/01_timestamp_sub_funcs.up.sql.
  comment on function wt_sub_seconds is 'wt_sub_seconds returns ts - sec.';
  comment on function wt_sub_seconds_from_now is 'wt_sub_seconds_from_now returns current_timestamp - sec.';

  -- Fixes incorrect comments in 2/04_oidc.up.sql
  comment on table auth_oidc_method is
    'auth_oidc_method entries are the current oidc auth methods configured for existing scopes.';
  comment on table auth_oidc_account is
    'auth_oidc_account entries are subtypes of auth_account and represent an oidc account.';

commit;
