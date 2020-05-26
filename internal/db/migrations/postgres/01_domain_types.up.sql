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
    new.create_time = old.create_time;
    raise warning 'create_time cannot be set to %', new.create_time;
  end if;
  return new;
end;
$$ language plpgsql;

comment on function
  immutable_create_time_func()
is
  'function used in before update triggers to make create_time column immutable';

commit;
