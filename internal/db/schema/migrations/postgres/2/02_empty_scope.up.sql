begin;

alter domain wt_scope_id
  drop constraint wt_scope_id_check;

alter domain wt_scope_id
  add constraint wt_scope_id_check
  check(
    length(trim(value)) > 10
    or value = 'global'
    or value = 'empty'
  );
comment on domain wt_scope_id is
'"global", "empty", or random ID generated with github.com/hashicorp/vault/sdk/helper/base62';


alter table iam_scope_type_enm
  drop constraint only_predefined_scope_types_allowed,
   add constraint only_predefined_scope_types_allowed
       check(string in ('unknown', 'global', 'org', 'project', 'empty'));

insert into iam_scope_type_enm (string)
values ('empty');

alter table iam_scope
  drop constraint only_known_scope_types_allowed,
   add constraint only_known_scope_types_allowed
       check(
        (
          type = 'global'
          and parent_id is null
        )
        or (
          type = 'empty'
          and parent_id is null
        )
        or (
          type = 'org'
          and parent_id = 'global'
        )
        or (
          type = 'project'
          and parent_id is not null
          and parent_id != 'global'
          and parent_id != 'empty'
        )
       );

create table iam_scope_empty (
  scope_id wt_scope_id primary key
    references iam_scope(public_id)
    on delete cascade
    on update cascade
    constraint only_one_empty_scope_allowed
    check(
      scope_id = 'empty'
    ),
  name text unique
);

drop trigger iam_scope_insert on iam_scope;

create or replace function
  iam_sub_scopes_func()
  returns trigger
as $$
declare parent_type int;
begin
  if new.type = 'global' then
    insert into iam_scope_global (scope_id, name)
    values
      (new.public_id, new.name);
    return new;
  end if;
  if new.type = 'empty' then
    insert into iam_scope_empty (scope_id, name)
    values
      (new.public_id, new.name);
    return new;
  end if;
  if new.type = 'org' then
    insert into iam_scope_org (scope_id, parent_id, name)
    values
      (new.public_id, new.parent_id, new.name);
    return new;
  end if;
  if new.type = 'project' then
    insert into iam_scope_project (scope_id, parent_id, name)
    values
      (new.public_id, new.parent_id, new.name);
    return new;
  end if;
  raise exception 'unknown scope type';
end;
$$ language plpgsql;

create trigger
  iam_scope_insert
after
insert on iam_scope
  for each row execute procedure iam_sub_scopes_func();

create or replace function
  disallow_empty_scope_deletion()
  returns trigger
as $$
begin
  if old.type = 'empty' then
    raise exception 'deletion of empty scope not allowed';
  end if;
  return old;
end;
$$ language plpgsql;

create trigger
  iam_scope_disallow_empty_deletion
before
delete on iam_scope
  for each row execute procedure disallow_empty_scope_deletion();


create trigger
  immutable_columns
before
update on iam_scope_empty
  for each row execute procedure immutable_columns('scope_id');


drop trigger iam_sub_names on iam_scope;

-- iam_sub_names will allow us to enforce the different name constraints for
-- orgs and projects via a before update trigger on the iam_scope
-- table.
create or replace function
  iam_sub_names()
  returns trigger
as $$
begin
  if new.name != old.name then
    if new.type = 'global' then
      update iam_scope_global set name = new.name where scope_id = old.public_id;
      return new;
    end if;
    if new.type = 'empty' then
      update iam_scope_empty set name = new.name where scope_id = old.public_id;
      return new;
    end if;
    if new.type = 'org' then
      update iam_scope_org set name = new.name where scope_id = old.public_id;
      return new;
    end if;
    if new.type = 'project' then
      update iam_scope_project set name = new.name where scope_id = old.public_id;
      return new;
    end if;
    raise exception 'unknown scope type';
  end if;
  return new;
end;
$$ language plpgsql;

create trigger
  iam_sub_names
before
update on iam_scope
  for each row execute procedure iam_sub_names();

insert into iam_scope (public_id, name, type, description)
  values ('empty', 'empty', 'empty', 'Empty Scope');

commit;
