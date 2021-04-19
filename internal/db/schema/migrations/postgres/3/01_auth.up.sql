begin;


-- this constraint is intended to ensure that a user cannot have more than one
-- account per auth_method
alter table auth_account
  add constraint auth_account_auth_method_id_public_id_uq
    unique(auth_method_id, iam_user_id);

commit;