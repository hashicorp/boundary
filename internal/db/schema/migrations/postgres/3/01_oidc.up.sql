begin;


-- auth_oidc_scope entries are the optional scopes for a specific oidc auth
-- method.  There can be 0 or more for each parent oidc auth method.  If an auth
-- method has any scopes, they will be added to provider requests along with the
-- default of "openid". 
create table auth_oidc_scope (
  create_time wt_timestamp,
  oidc_method_id wt_public_id 
    constraint auth_oidc_method_fkey
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  scope text not null
    constraint scope_must_not_be_empty
       check(length(trim(scope)) > 0) 
    constraint scope_must_be_less_than_1024_chars
      check(length(trim(scope)) < 1024)
    constraint scope_must_not_be_openid -- the default scope is not allowed, since it's redundant
      check(trim(scope) != 'openid'),
  primary key(oidc_method_id, scope)
);
comment on table auth_oidc_scope is
'auth_oidc_scope entries are the optional scopes for a specific oidc auth method.  There can be 0 or more for each parent oidc auth method.  If an auth method has any scopes, they will be added to provider requests along with the openid default.';


commit;
