-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table server_type_enm (
  name text primary key
    constraint only_predefined_server_types_allowed
      check (
        name in (
          'controller',
          'worker'
        )
      )
);
comment on table server_type_enm is
  'server_type_enm is an enumeration table for server types. '
  'It contains rows for representing servers as either a controller or worker.';

insert into server_type_enm (name) values
  ('controller'),
  ('worker');

alter table server
    add constraint server_type_enm_fkey
      foreign key (type) references server_type_enm(name)
        on update cascade
        on delete restrict;

commit;
