-- wtt_load_colors tests the wtt_load test helper function for the colors persona.
begin;
  select plan(1);
  select lives_ok($$select wtt_load('colors', 'iam', 'kms', 'auth', 'hosts', 'targets')$$);

  select * from finish();
rollback;
