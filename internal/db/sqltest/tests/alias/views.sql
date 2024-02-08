-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(1);
select wtt_load('widgets', 'iam', 'kms', 'auth');

select has_view('alias_view', 'view for reading generic alias data does not exist');

select * from finish();
rollback;
