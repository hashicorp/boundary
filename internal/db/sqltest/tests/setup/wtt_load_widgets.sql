-- wtt_load_widgets tests the wtt_load test helper function for the widgets persona.
begin;
  select plan(1);

  select lives_ok($$select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets')$$);

  select * from finish();
rollback;
