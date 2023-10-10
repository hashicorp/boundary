-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table policy (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null
);
comment on table policy is
'policy contains entries that represent an abstract policy';

create table storage_policy (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null,
  retention_days integer not null,
  name wt_name,
  description wt_description,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  constraint storage_policy_name_uq
    unique(scope_id, name)
);
comment on table storage_policy is
'storage_policy is a subtype of policy and contains entries that codify a'
'storage policy and how long to keep session recordings';

create trigger default_create_time_column before insert on storage_policy
  for each row execute procedure default_create_time();

create trigger update_time_column before update on storage_policy
  for each row execute procedure update_time_column();

create trigger update_version_column after update on storage_policy
  for each row execute procedure update_version_column();

create trigger immutable_columns before update on storage_policy
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create or replace function storage_policy_scope_id_valid() returns trigger
as $$
begin
  perform from iam_scope where public_id = new.scope_id and type in ('global', 'org');
  if not found then
    raise exception 'invalid scope type for storage policy creation';
  end if;
  return new;
end;
$$ language plpgsql;
comment on function storage_policy_scope_id_valid is
'storage_policy_scope_id_valid is a trigger function that checks that the'
'scope_id being inserted is a global or org level scope.';

create trigger storage_policy_scope_id_valid before insert on storage_policy
  for each row execute procedure storage_policy_scope_id_valid();

create or replace function insert_policy_subtype() returns trigger
as $$
begin
  insert into policy
    (public_id, scope_id)
  values
    (new.public_id, new.scope_id);
  return new;
end;
$$ language plpgsql;

create trigger insert_policy_subtype before insert on storage_policy
  for each row execute procedure insert_policy_subtype();

create or replace function delete_policy_subtype() returns trigger
as $$
begin
  delete from policy where public_id = old.public_id;
  return null;
end;
$$ language plpgsql;

create trigger delete_policy_subtype after delete on storage_policy
  for each row execute procedure delete_policy_subtype();

create table scope_storage_policy_override_behavior_enm (
  name text primary key
  constraint only_predefined_override_behaviors_allowed
  check (
    name in (
      'restricted',
      'safer-only',
      'allowed'
    )
  )
);
comment on table scope_storage_policy_override_behavior_enm is
'scope_storage_policy_override_behavior_enm is an enumeration table for storage'
'policy override behaviors';

insert into scope_storage_policy_override_behavior_enm (name)
values
  ('restricted'),
  ('safer-only'),
  ('allowed');

-- TBD: There's no triggers on storage_policy that would populate this table.
-- Will this happen in code?
create table scope_storage_policy (
  scope_id wt_scope_id primary key,
  storage_policy_id wt_public_id not null,
  override_behavior text not null,
  constraint scope_storage_policy_scope_id_fkey
    foreign key (scope_id)
    references iam_scope (public_id)
    on update cascade
    on delete cascade,
  constraint scope_storage_policy_storage_policy_id_fkey
    foreign key (storage_policy_id)
    references storage_policy (public_id)
    on update cascade
    on delete cascade,
  constraint scope_storage_policy_override_behavior_fkey
    foreign key (override_behavior)
    references scope_storage_policy_override_behavior_enm (name)
    on update restrict
    on delete restrict
);
comment on table scope_storage_policy is
'scope_storage_policy is an association table between a scope and a storage'
'policy. The scope can only be global or the same scope present in the storage'
'policy to be associated';

create trigger immutable_columns before update on scope_storage_policy
  for each row execute procedure immutable_columns('scope_id');

create or replace function scope_storage_policy_scope_id_valid() returns trigger
as $$
begin
  -- Check if the scope_id on the storage_policy matches the scope id for this
  -- scope + storage policy association.
  perform from storage_policy where public_id = new.storage_policy_id and scope_id = new.scope_id;
  if not found then
    -- If the scopes don't match, the only other valid case is the global scope.
    perform from iam_scope where public_id = new.scope_id and type in ('global');
    if not found then
      raise exception 'invalid scope_id for scope_storage_policy association';
    end if;
  end if;
  return new;
end;
$$ language plpgsql;
comment on function scope_storage_policy_scope_id_valid is
'scope_storage_policy_scope_id_valid is a trigger function that checks that the'
'scope_id being inserted is either global or the same org as the storage policy'
'we want to associate';

-- TBD: Given that storage_policy_id is not immutable, should there also be a
-- 'before update' trigger with the same procedure?
create trigger scope_storage_policy_scope_id_valid before insert on scope_storage_policy
  for each row execute procedure scope_storage_policy_scope_id_valid();

commit;
