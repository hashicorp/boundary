-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

-- org-delete tests:
--  deleting an org

begin;
  select plan(1);

  prepare delete_org as
    delete from iam_scope
     where type = 'org'
       and public_id = 'o__foodtruck';

  select lives_ok('delete_org');

  select * from finish();
rollback;
