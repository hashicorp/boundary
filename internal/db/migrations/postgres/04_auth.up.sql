begin;

  -- base table for auth methods
  create table auth_method (
    public_id wt_public_id primary key
  );


  -- base table for auth accounts
  create table auth_account (
    public_id wt_public_id primary key
  );

commit;
