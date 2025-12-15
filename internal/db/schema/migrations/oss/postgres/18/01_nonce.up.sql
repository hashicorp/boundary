-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- This migration exists to generalize the nonce behavior since we need it for
-- more than recovery nonces.

create table nonce_type_enm (
  name text primary key
    constraint only_predefined_nonce_types_allowed
      check (
        name in (
          'recovery',
          'worker-auth'
        )
      )
);
comment on table nonce_type_enm is
  'nonce_type_enm is an enumeration table for nonce types. '
  'It contains rows for representing nonces as either for recovery or worker authentication purposes.';

insert into nonce_type_enm (name) values
  ('recovery'),
  ('worker-auth');

-- Drop existing triggers
drop trigger default_create_time_column on recovery_nonces;
drop trigger immutable_columns on recovery_nonces;

-- Update table name
alter table recovery_nonces rename to nonce;

-- Add purpose field
alter table nonce
  add column purpose text not null default 'recovery'
    constraint nonce_type_enm_fkey
      references nonce_type_enm(name)
      on update cascade
      on delete restrict;

alter table nonce
  alter column purpose drop default;


-- Recreate triggers
create trigger default_create_time_column before insert on nonce
  for each row execute procedure default_create_time();

create trigger immutable_columns before update on nonce
  for each row execute procedure immutable_columns('nonce', 'create_time', 'purpose');

commit;
