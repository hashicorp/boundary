begin;

create domain wt_public_id as text
check(
  length(trim(value)) > 10
);
comment on domain wt_public_id is
'Random ID generated with github.com/hashicorp/vault/sdk/helper/base62';

create domain wt_timestamp as
  timestamp with time zone
  default current_timestamp;
comment on domain wt_timestamp is
'Standard timestamp for all create_time and update_time columns';


create or replace function
  update_time_column()
  returns trigger
as $$
begin
  if row(new.*) is distinct from row(old.*) then
    new.update_time = now();
    return new;
  else
    return old;
  end if;
end;
$$ language plpgsql;

comment on function
  update_time_column()
is
  'function used in before update triggers to properly set update_time columns';

create or replace function
  immutable_create_time_func()
  returns trigger
as $$
begin
  if new.create_time is distinct from old.create_time then
    raise warning 'create_time cannot be set to %', new.create_time;
    new.create_time = old.create_time;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  immutable_create_time_func()
is
  'function used in before update triggers to make create_time column immutable';
  
create or replace function
  default_create_time()
  returns trigger
as $$
begin
  if new.create_time is distinct from now() then
    raise warning 'create_time cannot be set to %', new.create_time;
    new.create_time = now();
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  default_create_time()
is
  'function used in before insert triggers to set create_time column to now';


-- update_version_column() will increment the version column whenever row data
-- is updated.  Additionally, it allows the version column to be explicitly
-- updated. 
create or replace function
  update_version_column()
  returns trigger
as $$
begin
  if row(new.*) is distinct from row(old.*) then
    -- check if we're not trying to explicitly update the version column, which
    -- should be allowed. 
    if new.version = old.version then
      new.version = old.version + 1;
      return new;
    else
      -- return new, so version can be explicitly updated.
      return new;
    end if;
  else
    -- nothing was updated, so return the old row data
    return old;
  end if;
end;
$$ language plpgsql;

comment on function
  update_time_column()
is
  'function used in before update triggers to properly set version columns';

commit;
