begin;

alter table auth_oidc_account
  add column token_claims text;
alter table auth_oidc_account
  add column userinfo_claims text;

commit;