-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table target_address (
    target_id wt_public_id primary key,
    address text not null
      -- the following constraints are used to validate the length requirements of a dns name
      -- note the address column can also contain other network types such as ipv4
      constraint address_must_be_more_than_2_characters
      check(length(trim(address)) > 2)
      constraint address_must_be_less_than_256_characters
      check(length(trim(address)) < 256),
    constraint target_fkey foreign key (target_id)
        references target (public_id)
        on delete cascade
        on update cascade
  );
  comment on table target_address is
    'target_address entries represent a network address assigned to a target.';

  create trigger immutable_columns before update on target_address
    for each row execute function immutable_columns('target_id');

  insert into oplog_ticket (name, version)
    values
      ('target_address', 1);

commit;