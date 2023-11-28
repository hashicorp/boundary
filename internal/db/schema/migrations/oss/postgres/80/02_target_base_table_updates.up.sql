-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add update_time to base target table.
  -- It already has the create time.
  alter table target add column update_time wt_timestamp;

  -- Update rows with current values
  update target
    set update_time = target_tcp.update_time
    from target as t
    left join target_tcp on t.public_id = target_tcp.public_id;
  update target
    set update_time = target_ssh.update_time
    from target as t
    left join target_ssh on t.public_id = target_ssh.public_id;

  -- Add trigger to update the new column on every subtype update.
  create function update_target_table_update_time() returns trigger
  as $$
  begin
    update target set update_time = now() where public_id = new.public_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_target_table_update_time() is
    'update_target_table_update_time is used to automatically update the update_time '
    'of the base table whenever one of the subtype tables are updated';

  create trigger update_target_table_update_time before update on target_tcp
    for each row execute procedure update_target_table_update_time();
  create trigger update_target_table_update_time before update on target_ssh
    for each row execute procedure update_target_table_update_time();

  -- Add new indexes for the update time queries.
  create index target_create_time_public_id_idx
      on target (create_time desc, public_id asc);
  create index target_update_time_public_id_idx
      on target (update_time desc, public_id asc);

  analyze target;

commit;
