-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  select plan(8);

  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets');

  insert into target_ssh
    (project_id, public_id, name)
  values
    ('p____bwidget', 'tssh____wbwh', 'Test SSH Target Type W/ HostSet'),
    ('p____bwidget', 'tssh___wbwha', 'Test SSH Target Type W/ Address');

  insert into target_tcp
    (project_id, public_id, name)
  values
    ('p____bwidget', 'ttcp____wbwh', 'Test TCP Target Type W/ HostSet'),
    ('p____bwidget', 'ttcp___wbwha', 'Test TCP Target Type W/ Address');

  insert into target_host_set
    (project_id, target_id, host_set_id)
  values
    ('p____bwidget', 'tssh____wbwh', 's___1wb-plghs'),
    ('p____bwidget', 'ttcp____wbwh', 's___1wb-plghs');

  insert into target_address
    (target_id, address)
  values
    ('tssh___wbwha', '8.6.4.2'),
    ('ttcp___wbwha', '8.6.4.2');

  -- validate ssh target type with host set
  select is(target_type, 'ssh target') from whx_host_dimension_source where target_id = 'tssh____wbwh';

  -- validate ssh target type with address
  select is(target_type, 'ssh target') from whx_host_dimension_source where target_id = 'tssh___wbwha';

  -- validate tcp target type with host set
  select is(target_type, 'tcp target') from whx_host_dimension_source where target_id = 'ttcp____wbwh';

  -- validate tcp target type with address
  select is(target_type, 'tcp target') from whx_host_dimension_source where target_id = 'ttcp___wbwha';

rollback;