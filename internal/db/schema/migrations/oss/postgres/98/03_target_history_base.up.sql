-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- This migration refactors target history to a base + subtype table design,
-- like we have for hosts. This design has a target_history_base table (the base
-- table) which holds all history ids for all target subtypes that have history
-- subtype tables. Data is inserted into or deleted from this base table via
-- triggers on each subtype table.
begin;
  create table target_history_base(
    history_id wt_url_safe_id primary key
  );
  comment on table target_history_base is
    'target_history_base is a base history table '
    'for target subtype history tables.';

  create function insert_target_history_subtype() returns trigger
  as $$
  begin
    insert into target_history_base
      (history_id)
    values
      (new.history_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_target_history_subtype() is
    'insert_target_history_subtype() is a before insert trigger'
    'function for subtypes of target_history_base';

  create function delete_target_history_subtype() returns trigger
  as $$
  begin
    delete
      from target_history_base
      where history_id = old.history_id;
    return null;
  end;
  $$ language plpgsql;
  comment on function delete_target_history_subtype() is
    'delete_target_history_subtype() is an after delete trigger'
    'function for subtypes of target_history_base';

  -- Update existing SSH target history table to follow the new pattern.
  -- First, backfill target_history_base with existing SSH history.
  insert into target_history_base (history_id)
    select history_id from target_ssh_hst;

  -- Next, set target_ssh_hst's history_id field to be a FK of the base table.
  alter table target_ssh_hst
    add constraint target_history_base_fkey
      foreign key (history_id)
        references target_history_base (history_id)
        on delete cascade
        on update cascade;

  -- Finally, add new triggers to target_ssh_hst to automatically insert into
  -- target_history_base from now on.
  create trigger hst_before_insert before insert on target_ssh_hst
    for each row execute function insert_target_history_subtype();
  create trigger hst_after_delete after delete on target_ssh_hst
    for each row execute function delete_target_history_subtype();
commit;