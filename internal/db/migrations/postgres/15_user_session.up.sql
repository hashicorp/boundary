begin;

  -- an iam_user can have 0 to many user_sessions
  -- an auth method can have 0 to many user_sessions
  -- a user session belongs to 1 and only 1 iam_user
  -- a user session belongs to 1 and only 1 auth methods
  create table user_session (
    public_id wt_public_id primary key,
    token text not null unique,
    iam_scope_id wt_public_id not null
      references iam_scope (public_id)
      on delete cascade
      on update cascade,
    iam_user_id wt_public_id not null unique -- read only
        references iam_user (public_id)
        on delete cascade
        on update cascade,
    auth_method_id wt_private_id not null
        references auth_method (auth_method_id)
        on delete cascade
        on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    unique(scope_id, name)
  );

  create trigger
    update_time_column
  before update on user_session
    for each row execute procedure update_time_column();

  create trigger
    immutable_create_time
  before
  update on user_session
    for each row execute procedure immutable_create_time_func();

  create trigger
    default_create_time_column
  before
  insert on user_session
    for each row execute procedure default_create_time();

  insert into oplog_ticket (name, version)
  values
    ('user_session', 1);

commit;
