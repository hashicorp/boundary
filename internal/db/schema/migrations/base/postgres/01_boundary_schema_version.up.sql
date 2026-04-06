-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;
create table boundary_schema_version (
	edition text   primary key,
	version bigint not null
);
commit;
