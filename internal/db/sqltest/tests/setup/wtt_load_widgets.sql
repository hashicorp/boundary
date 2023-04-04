-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- wtt_load_widgets tests the wtt_load test helper function for the widgets persona.
begin;
  select plan(1);

  select lives_ok($$select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials', 'sessions')$$);

  select * from finish();
rollback;
