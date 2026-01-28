-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  insert into target_rdp
    (project_id, public_id, name)
  values
    ('p____bwidget', 'trdp______wb', 'Big Widget RDP Target'),
    ('p____swidget', 'trdp______ws', 'Small Widget RDP Target');

  select is(count(*), 1::bigint) from target_all_subtypes where public_id = 'trdp______wb';
  select is(type,     'rdp')     from target_all_subtypes where public_id = 'trdp______wb';
  select is(count(*), 1::bigint) from target_all_subtypes where public_id = 't_________wb';
  select is(type,     'tcp')     from target_all_subtypes where public_id = 't_________wb';

  select * from finish();
rollback;
