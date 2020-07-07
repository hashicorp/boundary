begin;

  drop view auth_token_account cascade;
  drop table auth_token cascade;

  drop function update_last_access_time cascade;
  drop function immutable_auth_token_columns cascade;
  drop function expire_time_not_older_than_token cascade;

commit;
