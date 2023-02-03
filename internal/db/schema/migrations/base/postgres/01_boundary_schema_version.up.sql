-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
create table boundary_schema_version (
	edition text   primary key,
	version bigint not null
);
commit;
