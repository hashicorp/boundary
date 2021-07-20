-- wtt_load tests the wtt_load test helper function.
begin;
  select plan(6);

  -- invalid or missing args
  select throws_ok($$select wtt_load('unknown', 'iam')$$);
  select throws_ok($$select wtt_load('colors', 'unknown')$$);
  select throws_ok($$select wtt_load('colors')$$);
  select throws_ok($$select wtt_load()$$);

  -- incorrect order since auth depends on iam
  select throws_ok($$select wtt_load('colors', 'auth', 'iam')$$);

  -- missing a dependancy, auth depends on iam
  select throws_ok($$select wtt_load('colors', 'auth')$$);

  select * from finish();
rollback;
