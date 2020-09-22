begin;

  drop function update_iam_user_auth_account;
  drop function insert_auth_account_subtype;
  drop function insert_auth_method_subtype;

  drop table auth_account cascade;
  drop table auth_method cascade;

commit;
