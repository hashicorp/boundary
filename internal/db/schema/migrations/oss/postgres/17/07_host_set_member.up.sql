begin;

  -- Add a version column and trigger to the generic host set table so it can be
  -- used as an aggregate for members
  alter table host_set add column version wt_version;
  create trigger update_version_column after update on host_set
    for each row execute procedure update_version_column();

  -- This creates non-type-specific set membership tables and migrates the old
  -- data over.

  create table host_set_member (
    host_id wt_public_id not null,
    set_id wt_public_id not null,
    catalog_id wt_public_id not null,
    primary key(host_id, set_id),
    foreign key (catalog_id, host_id) -- fk1
      references host (catalog_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (catalog_id, set_id) -- fk2
      references host_set (catalog_id, public_id)
      on delete cascade
      on update cascade
  );

  create trigger immutable_columns before update on host_set_member
    for each row execute procedure immutable_columns('host_id', 'set_id', 'catalog_id');

  create or replace function insert_host_set_member()
    returns trigger
  as $$
  begin
    select host_set.catalog_id
      into new.catalog_id
    from host_set
    where host_set.public_id = new.set_id;
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_host_set_member before insert on host_set_member
    for each row execute procedure insert_host_set_member();

  insert into oplog_ticket (name, version)
  values
    ('host_set_member', 1);

commit;