-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Add the create_time and update_time columns to the worker_auth_authorized
-- table and set the values for existing rows to -infinity since we only know
-- that the existing rows were created at some point in time prior to "now".
alter table worker_auth_authorized
  add column create_time timestamp with time zone default '-infinity',
  add column update_time timestamp with time zone default '-infinity'
;

-- Now that values for the existing rows are set, change the create_time and
-- update_time columns to follow our standard pattern.
alter table worker_auth_authorized
  alter column create_time drop default,
  alter column update_time drop default,
  alter column create_time type wt_timestamp,
  alter column update_time type wt_timestamp
;

create trigger default_create_time_column before insert on worker_auth_authorized
  for each row execute procedure default_create_time();

create trigger update_time_column before update on worker_auth_authorized
  for each row execute procedure update_time_column();

-- Add the worker_auth_authorized_state_enm table and insert enum the values
create table worker_auth_authorized_state_enm (
  state text primary key
    constraint only_predefined_worker_auth_authorized_states_allowed
      check (
          state in ('previous', 'current')
        )
);
comment on table credential_vault_token_status_enm is
  'worker_auth_authorized_state_enm is an enumeration table for the state column in the worker_auth_authorized table.';

insert into worker_auth_authorized_state_enm (state)
values
  ('previous'),
  ('current');

-- Add the state column to the worker_auth_authorized table and set the value
-- for existing rows to null.
alter table worker_auth_authorized
  add column state text
    constraint worker_auth_authorized_state_enm_fkey
      references worker_auth_authorized_state_enm(state)
      on delete restrict
      on update cascade,
  add constraint worker_auth_authorized_worker_id_state_uq
    unique(worker_id, state)
;

-- The worker_auth_authorized table may contain multiple rows for the same
-- worker_id. For each worker_id in the table, we need to pick one row and set
-- its state to 'current'. There is no way to be sure that we will pick the
-- correct row but we can use the xmin system column and the postgresql age()
-- function to make an educated guess.
--
-- xmin is the transaction id (xid) of the transaction that inserted that
-- version of the row. The age(xid) function returns the age of the given xid
-- relative to the xid of the current transaction or the next-to-be-assigned
-- xid if the the age() is called outside of a transition.
--
-- We use the xmin column and age function to select the row most recently
-- inserted or updated for each worker_id and set the state value for that row
-- to 'current'.
--
-- References:
--  * xmin system column: https://www.postgresql.org/docs/14/ddl-system-columns.html
--  * age function: https://github.com/postgres/postgres/blob/REL_14_STABLE/src/backend/utils/adt/xid.c#L97-L111
--  * xid data type: https://www.postgresql.org/docs/14/datatype-oid.html
with
  last_inserted_rows (worker_id, row_age) as (
    select worker_id, min(age(xmin))
    from worker_auth_authorized
    group by worker_id
  ),
  current_keys (worker_key_identifier) as (
    select worker_key_identifier
    from worker_auth_authorized
    where (worker_id, age(xmin)) in (select * from last_inserted_rows)
  )
update worker_auth_authorized
set state = 'current'
where worker_key_identifier in (select worker_key_identifier from current_keys);

delete from worker_auth_authorized
where state is null;

alter table worker_auth_authorized
  alter column state set not null
;

drop trigger immutable_columns on worker_auth_authorized;
-- this trigger is updated in 56/05_mutable_ciphertext_columns.up.sql
create trigger immutable_columns before update on worker_auth_authorized
  for each row execute function immutable_columns('worker_key_identifier', 'worker_id', 'worker_signing_pub_key',
                                                  'worker_encryption_pub_key', 'controller_encryption_priv_key', 'key_id', 'nonce', 'create_time');

-- insert_worker_auth_authorized is a before insert trigger function for the
-- worker_auth_authorized table. The worker_auth_authorized table is a child
-- table of server_worker. A row contains a set encryption keys for a
-- server_worker that are unique to that worker. A server_worker can only have
-- two rows in the worker_auth_authorized table: one with a state of 'current'
-- and one with the state of 'previous'.
--
-- A controller encrypts messages to a worker with the worker's 'current' keys.
-- A worker can encrypt messages to a controller with the worker's 'current'
-- or 'previous' keys.
--
-- When a new row of keys is inserted for a worker, the new row of keys is
-- marked as 'current', the 'current' row of keys is changed to 'previous',
-- and the 'previous' row of keys is deleted.
create function insert_worker_auth_authorized() returns trigger
as $$
begin
  -- delete the worker's 'previous' row of keys
  delete from worker_auth_authorized
  where worker_id = new.worker_id
    and state = 'previous';
  -- change the worker's 'current' row of keys to 'previous'
  update worker_auth_authorized
  set state = 'previous'
  where worker_id = new.worker_id
    and state = 'current';
  -- set the worker's new row of keys to 'current'
  new.state = 'current';
  return new;
end;
$$ language plpgsql;
comment on function insert_worker_auth_authorized is
  'insert_worker_auth_authorized is a before insert trigger function for the worker_auth_authorized table.';

create trigger insert_worker_auth_authorized before insert on worker_auth_authorized
  for each row execute function insert_worker_auth_authorized();

commit;
