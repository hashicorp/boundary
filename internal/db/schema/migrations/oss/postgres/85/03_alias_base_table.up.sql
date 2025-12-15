-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table alias (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
      constraint iam_scope_fkey
        references iam_scope (public_id)
        on delete cascade
        on update cascade
      constraint alias_must_be_in_global_scope
        check(
          scope_id = 'global'
        ),
    value wt_alias not null
      constraint alias_value_uq
        unique,
    constraint alias_scope_id_value_public_id_uq
      unique(scope_id, value, public_id)
  );
  comment on table alias is
    'alias is a base table for the alias type. '
    'Each row is owned by a single scope and maps 1-to-1 to a row in one of the alias subtype tables.';

  create trigger immutable_columns before update on alias
    for each row execute procedure immutable_columns('public_id', 'scope_id');

  -- insert_alias_subtype() is a before insert trigger
  -- function for subtypes of alias
  create function insert_alias_subtype() returns trigger
  as $$
  begin
    insert into alias
      (public_id, value, scope_id)
    values
      (new.public_id, new.value, new.scope_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_alias_subtype() is
    'insert_alias_subtype() inserts a record into the base alias table when a corresponding record is inserted into the subtype table';


  -- delete_alias_subtype() is an after delete trigger
  -- function for subtypes of alias
  create function delete_alias_subtype() returns trigger
  as $$
  begin
    delete from alias
    where 
      public_id = old.public_id;
    return null;
  end;
  $$ language plpgsql;
  comment on function delete_alias_subtype() is
    'delete_alias_subtype() deletes the base alias record when the corresponding record is deleted from the subtype table';

  create function update_alias_subtype() returns trigger
  as $$
  begin
    update alias set value = new.value where public_id = new.public_id and new.value != value;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_alias_subtype() is
    'update_alias_subtype() updates the base table value column with the new value from the subtype table';

commit;
