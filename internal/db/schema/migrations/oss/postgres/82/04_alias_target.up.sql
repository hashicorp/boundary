-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table alias_target (
    public_id wt_public_id primary key,
    name wt_name,
    description wt_description,
    scope_id wt_scope_id not null
      constraint iam_scope_global_fkey
        references iam_scope_global (scope_id)
        on delete cascade
        on update cascade,
    value wt_target_alias not null,
    destination_id wt_public_id
      constraint target_fkey
        references target (public_id)
        on delete set null
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    host_id wt_public_id
      constraint destination_id_set_when_host_id_is_set
        check(
          destination_id is not null
          or
          (
            destination_id is null
            and
            host_id is null
          )
        ),
    constraint alias_target_scope_id_name_uq
      unique(scope_id, name),
    constraint alias_fkey
      foreign key (scope_id, value, public_id)
        references alias (scope_id, value, public_id)
        on delete cascade
        on update cascade
        deferrable initially deferred
  );
  comment on table alias_target is
    'alias_target is a subtype of alias. '
    'Each row is owned by a single scope and maps 1-to-1 to a row in the alias table.';

  create index alias_target_create_time_public_id_idx
      on alias_target (create_time desc, public_id desc);
      
  create index alias_target_update_time_public_id_idx
      on alias_target (update_time desc, public_id desc);

  create function delete_host_id_if_destination_id_is_null() returns trigger
    as $$
  begin
    if new.destination_id is null then
      new.host_id = null;
    end if;
    return new;
  end;
  $$ language plpgsql;

  create function alias_scope_is_parent_to_destination_scope() returns trigger
    as $$
  begin
    if new.scope_id = 'global' then
      return new;
    end if;
    if new.destination_id is null then
      return new;
    end if;

    perform from
      target t
    where
    t.public_id = new.destination_id
    and
    (
      t.project_id = new.scope_id
      or
      new.scope_id = (select parent_id from iam_scope where public_id = t.project_id)
    );
    if not found then
      raise exception 'alias scope must be the same or a parent to the destination scope';
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger delete_host_id_if_destination_id_is_null before update on alias_target
    for each row execute procedure delete_host_id_if_destination_id_is_null();

  -- this should be an after trigger, since the other constraints on the table
  -- provide more useful information if the fk references are incorrect.
  create trigger alias_scope_is_parent_to_destination_scope after insert or update on alias_target
    for each row execute procedure alias_scope_is_parent_to_destination_scope();

  create trigger insert_alias_subtype before insert on alias_target
    for each row execute procedure insert_alias_subtype();

  create trigger update_alias_subtype after update on alias_target
    for each row execute procedure update_alias_subtype();

  create trigger delete_alias_subtype after delete on alias_target
    for each row execute procedure delete_alias_subtype();

  create trigger update_version_column after update on alias_target
    for each row execute procedure update_version_column();

  create trigger update_time_column before update on alias_target
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on alias_target
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on alias_target
    for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');


  -- Alias delete tracking tables
  create table alias_target_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table alias_target_deleted is
  'alias_target_deleted holds the ID and delete_time of every deleted target alias. '
  'It is automatically trimmed of records older than 30 days by a job.';

  create trigger insert_alias_target_deleted after delete on alias_target
    for each row execute procedure insert_deleted_id('alias_target_deleted');

  create index alias_target_deleted_delete_time_idx on alias_target_deleted (delete_time);

  insert into oplog_ticket (name, version)
  values
    ('alias_target', 1);

commit;