begin;

  create table iam_group_member_user (
    create_time wt_timestamp,
    group_id wt_public_id
      references iam_group(public_id)
      on delete cascade
      on update cascade,
    member_id wt_public_id
      references iam_user(public_id)
      on delete cascade
      on update cascade,
    primary key (group_id, member_id)
  );

  -- get_scoped_principal_id is used by the iam_group_member view as a convient
  -- way to create <scope_id>:<member_id> to reference members from
  -- other scopes than the group's scope.
  create or replace function get_scoped_member_id(group_scope text, member_scope text, member_id text) returns text
  as $$
  begin
    if group_scope = member_scope then
      return member_id;
    end if;
    return member_scope || ':' || member_id;
  end;
  $$ language plpgsql;

  -- iam_group_member provides a consolidated view of group members.
  create view iam_group_member as
  select
    gm.create_time,
    gm.group_id,
    gm.member_id,
    u.scope_id as member_scope_id,
    g.scope_id as group_scope_id,
    get_scoped_member_id(g.scope_id, u.scope_id, gm.member_id) as scoped_member_id,
    'user' as type
  from
    iam_group_member_user gm,
    iam_user u,
    iam_group g
  where
    gm.member_id = u.public_id and
    gm.group_id = g.public_id;


commit;
