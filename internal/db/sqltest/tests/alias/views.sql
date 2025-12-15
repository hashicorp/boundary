-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(1);
select wtt_load('widgets', 'iam', 'kms', 'auth');

select has_view('alias_all_subtypes', 'view for reading generic alias data does not exist');

select * from finish();
rollback;
