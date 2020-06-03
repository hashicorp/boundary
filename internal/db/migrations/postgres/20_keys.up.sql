begin;

create table kms_key_entry_purpose_enm (
  string text not null primary key check(
    string in (
      'unknown',
      'root',
      'msp',
      'organization',
      'oplog',
      'database'
    )
  )
);
comment on table
  kms_key_entry_purpose_enm
is
  'table stores the kms key entry purpose enums';

insert into  kms_key_entry_purpose_enm (string)
values
  ('unknown'),
  ('root'),
  ('msp'),
  ('organization'),
  ('oplog'),
  ('database');

create table kms_key_entry_type_enm (
  string text not null primary key check(
    string in (
      'msp',
      'organization'
    )
  )
);
comment on table
  kms_key_entry_type_enm
is
  'table stores the kms key entry type enums';

insert into  kms_key_entry_type_enm (string)
values
  ('msp'),
  ('organization');

create table kms_key_entry (
  public_id wt_public_id primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  key_id text not null unique,
  key bytea not null,
  version int not null default 1,
  purpose text not null references kms_key_entry_purpose_enm(string), 
  kms_id text,
  parent_key_id text references kms_key_entry(key_id) on delete cascade on update cascade,
  scope_id wt_public_id not null references iam_scope(public_id) on delete cascade on update cascade,
  type text not null references kms_key_entry_type_enm(string) check(
      (
      type = 'msp'
      and kms_id is not null
    ) 
    or (
      type = 'organization'
      and (parent_key_id is not null or kms_id is not null)
    )
  ),
  unique(purpose, scope_id)
);
comment on table
  kms_key_entry
is
  'table stores the kms key entries';

create table kms_key_entry_msp (
  key_entry_public_id wt_public_id unique references kms_key_entry(public_id) on delete cascade on update cascade,
  primary key(key_entry_public_id)
);
comment on table
  kms_key_entry_msp
is
  'table stores the kms key entries for msps';

create table kms_key_entry_organization (
  key_entry_public_id wt_public_id unique references kms_key_entry(public_id) on delete cascade on update cascade,
  primary key(key_entry_public_id)
);
comment on table
  kms_key_entry_organization
is
  'table stores the kms key entries for organizations';

create or replace function 
  kms_key_entry_func() 
  returns trigger
as $$ 
begin 
  if new.type = 'organization' then
    insert into kms_key_entry_organization (key_entry_public_id)
    values
      (new.public_id);
    return new;
  end if;
  if new.type = 'msp' then
    insert into kms_key_entry_msp (key_entry_public_id)
    values
      (new.public_id);
    return new;
  end if;
  raise exception 'unknown kms key entry type';
end;
$$ language plpgsql;

create or replace function 
  kms_key_entry_immutable_type_func() 
  returns trigger
as $$ 
begin 
  if new.type != old.type then
    raise exception 'kms key type cannot be updated';
  end if;
  return new;
end;
$$ language plpgsql;

create trigger 
  kms_key_entry_insert
after
insert on kms_key_entry
  for each row execute procedure kms_key_entry_func();

create trigger 
  kms_key_entry_update
before 
update on kms_key_entry 
  for each row execute procedure kms_key_entry_immutable_type_func();


create trigger
update_time_column
before update on kms_key_entry
for each row execute procedure update_time_column();

create trigger
immutable_create_time
before
update on kms_key_entry
for each row execute procedure immutable_create_time_func();

create trigger
default_create_time_column
before
insert on kms_key_entry
for each row execute procedure default_create_time();

commit;