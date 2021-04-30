begin;

-- auth_oidc_account_claim_map entries are the optional claim maps from custom
-- claims to the standard claims of sub, name and email.  There can be 0 or more
-- for each parent oidc auth method. 
create table auth_oidc_account_claim_map (
  create_time wt_timestamp,
  oidc_method_id wt_public_id 
    constraint auth_oidc_method_fkey
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  from_claim text not null
    constraint from_claim_must_not_be_empty
       check(length(trim(from_claim)) > 0) 
    constraint from_claim_must_be_less_than_1024_chars
      check(length(trim(from_claim)) < 1024),
  to_claim text not null constraint to_claim_valid_values CHECK (to_claim IN ('sub', 'name', 'email')), -- intentionally case-sensitive matching
  primary key(oidc_method_id, to_claim)
);
comment on table auth_oidc_account_claim_map is
'auth_oidc_account_claim_map entries are the optional claim maps from custom claims to the standard claims of sub, name and email.  There can be 0 or more for each parent oidc auth method.';


create trigger
  default_create_time_column
before
insert on auth_oidc_account_claim_map
  for each row execute procedure default_create_time();


  commit;