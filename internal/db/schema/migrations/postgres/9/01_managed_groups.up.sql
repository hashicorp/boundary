begin;

-- The base abstract table
create table auth_managed_group (
  public_id wt_public_id
    primary key,
  auth_method_id wt_public_id
    not null,
  scope_id wt_scope_id
    not null,
  -- Ensure that if the auth method is deleted (which will also happen if the
  -- scope is deleted) this is deleted too
  constraint auth_method_fkey
    foreign key (auth_method_id) -- fk1
      references auth_method(public_id)
      on delete cascade
      on update cascade
);
comment on table auth_managed_group is
'auth_managed_group is the abstract base table for managed groups.';

-- Define the immutable fields of auth_managed_group
create trigger 
  immutable_columns
before
update on auth_managed_group
  for each row execute procedure immutable_columns('public_id', 'auth_method_id', 'scope_id');

commit;
