-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(4);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  -- validate the setup data
  select is(count(*), 1::bigint)
    from host_set hs
    join host_catalog hc on hs.catalog_id = hc.public_id
   where hc.project_id  = 'p____bwidget'
     and hc.public_id = 'c___wb-plghcl'
     and hs.public_id = 's___1wb-plghs';

  select is(count(*), 1::bigint)
    from host_set hs
    join host_catalog hc on hs.catalog_id = hc.public_id
   where hc.project_id  = 'p____swidget'
     and hc.public_id = 'c___ws-plghcl'
     and hs.public_id = 's___1ws-plghs';

  insert into target
    (project_id,     public_id)
  values
    ('p____bwidget', 'test______wb');

  prepare insert_valid_target_host_set as
    insert into target_host_set
      (project_id,     target_id,      host_set_id)
    values
      ('p____bwidget', 'test______wb', 's___1wb-plghs');
  select lives_ok('insert_valid_target_host_set', 'insert valid target_host_set failed');

  prepare insert_invalid_target_host_set as
    insert into target_host_set
      (project_id,     target_id,      host_set_id)
    values
      ('p____bwidget', 'test______wb', 's___1ws-plghs');
  select throws_ok('insert_invalid_target_host_set', '23503', null, 'insert invalid target_host_set succeeded');

  select * from finish();
rollback;
