-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table resource_enm (
    string text not null primary key
  );

  insert into resource_enm (string)
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