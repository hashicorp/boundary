-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(1);

  select has_index('wh_session_accumulating_fact',
                   'wh_session_accumulating_fact_session_pending_time_idx',
                   'session_pending_time',
                   'index for hcp billing views is missing' );

  select * from finish();
rollback;
