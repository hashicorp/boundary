-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  insert into target_ssh
    (project_id, public_id, name)
  values
    ('p____bwidget', 'tssh______wb', 'Big Widget SSH Target'),
    ('p____swidget', 'tssh______ws', 'Small Widget SSH Target');

  select is(count(*), 1::bigint) from target_all_subtypes where public_id = 'tssh______wb';
  select is(type,     'ssh')     from target_all_subtypes where public_id = 'tssh______wb';
  select is(count(*), 1::bigint) from target_all_subtypes where public_id = 't_________wb';
  select is(type,     'tcp')     from target_all_subtypes where public_id = 't_________wb';

  select * from finish();
rollback;
