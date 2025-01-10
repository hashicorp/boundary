-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table resource_enm (
    string text not null primary key
  );

  insert into resource_enm (string)
  values 
    ('*'),
    ('unknown'),
    ('scope'),
    ('user'),
    ('group'),
    ('role'),
    ('auth-method'),
    ('account'),
    ('auth-token'),
    ('host-catalog'),
    ('host-set'),
    ('host'),
    ('target'),
    ('controller'),
    ('worker'),
    ('session'),
    ('session-recording'),
    ('managed-group'),
    ('credential-store'),
    ('credential-library'),
    ('credential'),
    ('storage-bucket'),
    ('policy'),
    ('billing'),
    ('alias');

commit;