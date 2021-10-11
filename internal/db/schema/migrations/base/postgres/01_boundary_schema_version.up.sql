begin;
create table boundary_schema_version (
	edition text   primary key,
	version bigint not null
);
commit;
