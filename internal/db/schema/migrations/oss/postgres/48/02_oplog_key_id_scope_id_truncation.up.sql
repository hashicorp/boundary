begin;

  truncate table oplog_entry cascade; -- 💥

  alter table oplog_entry
    add column key_id text not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

  alter table oplog_entry
    add column scope_id text not null
      constraint iam_scope_fkey
        references iam_scope (public_id)
        on delete cascade
        on update cascade;

  create or replace function add_oplog_entry_scope_id() returns trigger
  as $$
  begin
    new.scope_id = (
      select scope_id
        from kms_root_key
        inner join kms_data_key on kms_root_key.private_id = kms_data_key.root_key_id
        inner join kms_data_key_version on kms_data_key.private_id = kms_data_key_version.data_key_id
        where kms_data_key_version.private_id = new.key_id
      );
    return new;
  end;
  $$ language plpgsql;
  comment on function add_oplog_entry_scope_id() is
    'add_oplog_entry_scope_id sets the scope_id based on the key_id';

  create trigger add_oplog_entry_scope_id before insert on oplog_entry
    for each row execute procedure add_oplog_entry_scope_id();

commit;
