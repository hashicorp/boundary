begin;

  create table iam_group_member (
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

commit;
