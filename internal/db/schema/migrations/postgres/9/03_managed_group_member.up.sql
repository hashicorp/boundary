begin;

-- Mappings of account to managed group
create table auth_managed_group_member_account (
  create_time wt_timestamp,
  managed_group_id wt_public_id
    references auth_managed_group(public_id)
    on delete cascade
    on update cascade,
  member_id wt_public_id
    references auth_account(public_id)
    on delete cascade
    on update cascade,
  primary key (managed_group_id, member_id)
);
comment on table auth_managed_group_member_account is
'auth_managed_group_member_account is the join table for managed groups and accounts.';

-- auth_immutable_managed_group_member_account() ensures that group members are immutable. 
create or replace function
  auth_immutable_managed_group_member_account()
  returns trigger
as $$
begin
    raise exception 'managed group members are immutable';
end;
$$ language plpgsql;

create trigger 
  default_create_time_column
before
insert on auth_managed_group_member_account
  for each row execute procedure default_create_time();

create trigger
  auth_immutable_managed_group_member_account
before
update on auth_managed_group_member_account
  for each row execute procedure auth_immutable_managed_group_member_account();

commit;
