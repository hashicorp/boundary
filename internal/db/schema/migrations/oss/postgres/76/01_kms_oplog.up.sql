-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

alter table oplog_entry
  drop constraint iam_scope_fkey,
  drop constraint kms_data_key_version_fkey;

drop trigger insert_oplog_entry on oplog_entry;
drop function insert_oplog_entry();
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