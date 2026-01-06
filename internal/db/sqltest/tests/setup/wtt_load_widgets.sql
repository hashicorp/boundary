-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- wtt_load_widgets tests the wtt_load test helper function for the widgets persona.
begin;
  select plan(1);

  select lives_ok($$select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials', 'sessions')$$);

  select * from finish();
rollback;
