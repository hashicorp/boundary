begin;

alter table auth_password_method
  add column auth_token_ttl int not null default 0
    constraint auth_token_ttl_cannot_be_negative
      check (auth_token_ttl >= 0);

commit;