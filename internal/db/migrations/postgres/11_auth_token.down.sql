begin;

  drop view auth_token_view cascade;
  drop table auth_token cascade;

  drop function update_last_access_time_column cascade;
  drop function immutable_auth_token_columns cascade;

commit;
