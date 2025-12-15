-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- remove the internal/db test tables from the migrations. 

drop table if exists db_test_user cascade;
drop table if exists db_test_car cascade;
drop table if exists db_test_rental cascade;
drop table if exists db_test_scooter cascade;
drop table if exists db_test_accessory cascade;
drop table if exists db_test_scooter_accessory cascade;


delete from oplog_ticket where name in
(
  'db_test_user',
  'db_test_car',
  'db_test_rental',
  'db_test_scooter',
  'db_test_accessory',
  'db_test_scooter_accessory'
);

commit;
