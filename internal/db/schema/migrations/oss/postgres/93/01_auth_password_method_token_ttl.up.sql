begin;

alter table auth_password_method
  add column token_ttl_seconds int not null default 0
    constraint token_ttl_seconds_cannot_be_negative
      check (token_time_to_live_seconds >= 0);

commit;