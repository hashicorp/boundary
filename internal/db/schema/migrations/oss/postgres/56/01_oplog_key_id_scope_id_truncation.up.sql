-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  truncate table oplog_entry, oplog_metadata;

  -- replaced by 77/04_alter_oplog_entry.up.sql
  alter table oplog_entry
    add column key_id kms_private_id not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade,
    add column scope_id wt_scope_id not null
      constraint iam_scope_fkey
        references iam_scope (public_id)
        on delete cascade
        on update cascade;
        
  -- replaced by 77/04_alter_oplog_entry.up.sql
  create function insert_oplog_entry() returns trigger
  as $$
  begin
    select scope_id into new.scope_id
      from kms_root_key
      inner join kms_data_key on kms_root_key.private_id = kms_data_key.root_key_id
      inner join kms_data_key_version on kms_data_key.private_id = kms_data_key_version.data_key_id
      where kms_data_key_version.private_id = new.key_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_oplog_entry() is
    'insert_oplog_entry sets the scope_id based on the key_id';

  create trigger insert_oplog_entry before insert on oplog_entry
    for each row execute procedure insert_oplog_entry();

commit;
