-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- For now at least the IDs will be the same as the name, because this allows us
-- to not have to persist some generated ID to worker and controller nodes.
-- Eventually we may want them to diverge, so we have both here for now.

create table server (
    private_id text,
    type text,
    name text not null unique
      constraint server_name_must_not_be_empty
      check(length(trim(name)) > 0),
    description text,
    address text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    primary key (private_id, type)
  );
  
create trigger immutable_columns before update on server
  for each row execute procedure immutable_columns('create_time');
  
create trigger default_create_time_column before insert on server
  for each row execute procedure default_create_time();

-- UPDATED in 18/01_nonce
create table recovery_nonces (
    nonce text primary key,
    create_time wt_timestamp
  );

create trigger default_create_time_column before insert on recovery_nonces
  for each row execute procedure default_create_time();

create trigger immutable_columns before update on recovery_nonces
  for each row execute procedure immutable_columns('nonce', 'create_time');

commit;
