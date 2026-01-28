-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table policy (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null
  -- constraints replaced in internal/db/schema/migrations/postgres/91/01_storage_policies.up.sql
  constraint policy_scope_id_fkey
    references iam_scope(public_id)
    on delete restrict
    on update cascade
);
comment on table policy is
'policy contains entries that represent an abstract policy';

create table policy_storage_policy (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null
  -- constraints replaced in internal/db/schema/migrations/postgres/91/01_storage_policies.up.sql
  constraint policy_storage_policy_scope_id_fkey
    references iam_scope(public_id)
    on delete restrict
    on update cascade,
  retain_for_days integer not null,
  retain_for_days_overridable boolean not null default true,
  delete_after_days integer not null,
  constraint delete_after_days_non_negative
    check(delete_after_days >= 0),
  constraint delete_after_days_greater_or_equal_than_retain_for_days
    check(delete_after_days >= retain_for_days or delete_after_days = 0),
  delete_after_days_overridable boolean not null default true,
  name wt_name,
  constraint policy_storage_policy_scope_id_name_uq
    unique(scope_id, name),
  description wt_description,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version
);
comment on table policy_storage_policy is
'policy_storage_policy is a subtype of policy and contains entries that codify '
'a storage policy and how long to keep session recordings';

create trigger default_create_time_column before insert on policy_storage_policy
  for each row execute procedure default_create_time();

create trigger update_time_column before update on policy_storage_policy
  for each row execute procedure update_time_column();

create trigger update_version_column after update on policy_storage_policy
  for each row execute procedure update_version_column();

create trigger immutable_columns before update on policy_storage_policy
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create function retain_for_days_and_delete_after_days_not_zero() returns trigger
as $$
begin
  if new.retain_for_days = 0 and new.delete_after_days = 0 then
    raise exception 'retain_for_days and delete_after_days are both zero';
  end if;
  return new;
end;
$$ language plpgsql;
comment on function retain_for_days_and_delete_after_days_not_zero is
'retain_for_days_and_delete_after_days_not_zero is a trigger function that '
'ensures that retain_for_days and delete_after_days cannot both be zero';

create trigger retain_for_days_and_delete_after_days_not_zero before insert or update on policy_storage_policy
  for each row execute procedure retain_for_days_and_delete_after_days_not_zero();

create function delete_after_days_zero_if_infinite_retain_for_days() returns trigger
as $$
begin
  if new.retain_for_days < 0 and new.delete_after_days != 0 then
    raise exception 'deletion period set on infinite retention period policy';
  end if;
  return new;
end;
$$ language plpgsql;
comment on function delete_after_days_zero_if_infinite_retain_for_days is
'delete_after_days_zero_if_infinite_retain_for_days is a trigger function that '
'ensures that if retain_for_days is set to infinity (-1), delete_after_days is '
'zero (working alongside the existing check constraints)';

create trigger delete_after_days_zero_if_infinite_retain_for_days before insert or update on policy_storage_policy
  for each row execute procedure delete_after_days_zero_if_infinite_retain_for_days();

create function policy_storage_policy_scope_id_valid() returns trigger
as $$
begin
  perform from iam_scope where public_id = new.scope_id and type in ('global', 'org');
  if not found then
    raise exception 'invalid scope type for storage policy creation';
  end if;
  return new;
end;
$$ language plpgsql;
comment on function policy_storage_policy_scope_id_valid is
'policy_storage_policy_scope_id_valid is a trigger function that checks that the '
'scope_id being inserted is a global or org level scope.';

create trigger policy_storage_policy_scope_id_valid before insert on policy_storage_policy
  for each row execute procedure policy_storage_policy_scope_id_valid();

create function insert_policy_subtype() returns trigger
as $$
begin
  insert into policy
    (public_id, scope_id)
  values
    (new.public_id, new.scope_id);
  return new;
end;
$$ language plpgsql;

create trigger insert_policy_subtype before insert on policy_storage_policy
  for each row execute procedure insert_policy_subtype();

create function delete_policy_subtype() returns trigger
as $$
begin
  delete from policy where public_id = old.public_id;
  return null;
end;
$$ language plpgsql;

create trigger delete_policy_subtype after delete on policy_storage_policy
  for each row execute procedure delete_policy_subtype();

create table scope_policy_storage_policy (
  scope_id wt_scope_id primary key
  constraint scope_policy_storage_policy_scope_id_fkey
    references iam_scope (public_id)
    on update cascade
    on delete cascade,
  storage_policy_id wt_public_id not null
  constraint scope_policy_storage_policy_storage_policy_id_fkey
    references policy_storage_policy (public_id)
    on update cascade
    on delete cascade
);
comment on table scope_policy_storage_policy is
'scope_policy_storage_policy is an association table between a scope and a storage '
'policy. The scope can only be global or the same scope present in the storage '
'policy to be associated';

create trigger immutable_columns before update on scope_policy_storage_policy
  for each row execute procedure immutable_columns('scope_id');

create function scope_policy_storage_policy_scope_id_valid() returns trigger
as $$
begin
  -- An org storage policy can only be applied to that specific org scope,
  -- whereas a `global` storage policy can be applied to any scope.
  perform from policy_storage_policy
  where ( public_id = new.storage_policy_id and scope_id = new.scope_id ) or scope_id = 'global';
  if not found then
      raise exception 'invalid scope_id for scope_storage_policy association';
  end if;
  return new;
end;
$$ language plpgsql;
comment on function scope_policy_storage_policy_scope_id_valid is
'scope_policy_storage_policy_scope_id_valid is a trigger function that '
'checks that the scope_id being inserted is either global or the same org as '
'the storage policy we want to associate';

create trigger scope_policy_storage_policy_scope_id_valid before insert on scope_policy_storage_policy
  for each row execute procedure scope_policy_storage_policy_scope_id_valid();

insert into oplog_ticket (name, version)
values
  ('policy', 1),
  ('policy_storage_policy', 1),
  ('scope_policy_storage_policy', 1);

commit;
