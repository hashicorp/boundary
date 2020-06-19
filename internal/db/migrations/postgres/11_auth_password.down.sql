begin;

  drop table auth_password_argon2_cred;
  drop table auth_password_argon2_conf;
  drop table auth_password_conf;
  drop table auth_password_credential;
  drop table auth_password_account;
  drop table auth_password_method;

  drop function insert_auth_password_conf_subtype;
  drop function insert_auth_password_credential_subtype;

end;
