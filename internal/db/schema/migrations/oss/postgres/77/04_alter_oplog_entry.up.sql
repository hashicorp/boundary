-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

alter table oplog_entry
  drop constraint iam_scope_fkey,
  drop constraint kms_data_key_version_fkey,
  add constraint kms_oplog_data_key_version_fkey
    foreign key(key_id)
      references kms_oplog_data_key_version (private_id)
      on delete restrict
      on update cascade;

drop trigger insert_oplog_entry on oplog_entry;
drop function insert_oplog_entry();
-- replaces function defined in 56/01_oplog_key_id_scope_id_truncation.up.sql
create function insert_oplog_entry() returns trigger
as $$
begin
  select scope_id into new.scope_id
    from kms_oplog_root_key
    inner join kms_oplog_data_key on kms_oplog_root_key.private_id = kms_oplog_data_key.root_key_id
    inner join kms_oplog_data_key_version on kms_oplog_data_key.private_id = kms_oplog_data_key_version.data_key_id
    where kms_oplog_data_key_version.private_id = new.key_id;
  return new;
end;
$$ language plpgsql;
comment on function insert_oplog_entry() is
  'insert_oplog_entry sets the oplog scope_id based on the key_id';

create trigger insert_oplog_entry before insert on oplog_entry
  for each row execute procedure insert_oplog_entry();

commit;
