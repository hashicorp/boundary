-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table resource_enm (
    name text primary key
    constraint only_predefined_resource_types_allowed
      check(
        name in (
          '*',
          'alias',
          'auth-method',
          'auth-token',
          'account',
          'billing',
          'controller',
          'credential',
          'credential-library',
          'credential-store',
          'group',
          'host',
          'host-catalog',
          'host-set',
          'managed-group',
          'policy',
          'role',
          'scope',
          'session',
          'session-recording',
          'storage-bucket',
          'target',
          'unknown',
          'user',
          'worker'
        )
      )
  );
  comment on table resource_enm is
    'resource_enm is an enumeration table for resource types.';

  -- Insert the predefined resource types
  insert into resource_enm (name)
  values 
    ('*'),
    ('alias'),
    ('auth-method'),
    ('auth-token'),
    ('account'),
    ('billing'),
    ('controller'),
    ('credential'),
    ('credential-library'),
    ('credential-store'),
    ('group'),
    ('host'),
    ('host-catalog'),
    ('host-set'),
    ('managed-group'),
    ('policy'),
    ('role'),
    ('scope'),
    ('session'),
    ('session-recording'),
    ('storage-bucket'),
    ('target'),
    ('unknown'),
    ('user'),
    ('worker');

commit;