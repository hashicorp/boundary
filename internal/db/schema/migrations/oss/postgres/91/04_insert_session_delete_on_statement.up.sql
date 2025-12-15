-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create function bulk_insert_deleted_ids() returns trigger
  as $$
  begin
    execute format('insert into %I (public_id, delete_time)
                         select o.public_id, now()
                           from old_table o;',
                   tg_argv[0]);
    return null;
  end;
  $$ language plpgsql;
  comment on function bulk_insert_deleted_ids is
    'bulk_insert_deleted_ids is a function that inserts records into the table '
    'specified by the first trigger argument. It takes the public IDs from the '
    'set of rows that where deleted and the current timestamp.';

  drop trigger insert_deleted_id on session;
  create trigger bulk_insert_deleted_ids
    after delete on session
    referencing old table as old_table
    for each statement execute function bulk_insert_deleted_ids('session_deleted');
commit;
