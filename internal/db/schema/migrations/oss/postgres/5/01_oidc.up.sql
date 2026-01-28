-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

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
      check(lower(trim(scope)) != 'openid'),
  primary key(oidc_method_id, scope)
);
comment on table auth_oidc_scope is
  'auth_oidc_scope entries are the optional scopes for a specific oidc auth method.  There can be 0 or more for each parent oidc auth method.  If an auth method has any scopes, they will be added to provider requests along with the openid default.';

create trigger default_create_time_column before insert on auth_oidc_scope
  for each row execute procedure default_create_time();


-- we will drop the oidc_auth_method_with_value_obj view, so we can recreate it
-- and add the oidc claim's scopes to the returned set.
drop view oidc_auth_method_with_value_obj;

-- oidc_auth_method_with_value_obj is useful for reading an oidc auth method
-- with its associated value objects (algs, auds, certs) as columns
-- with | delimited values.  The use of the postgres string_agg(...) to
-- aggregate the value objects into a column works because we are only pulling
-- in one column from the associated tables and that value is part of the
-- primary key and unique.  This view will make things like recursive listing of
-- oidc auth methods fairly straightforward to implement for the oidc repo. 
-- The view also includes an is_primary_auth_method bool
create view oidc_auth_method_with_value_obj as 
select 
  case when s.primary_auth_method_id is not null then
    true
  else false end
  as is_primary_auth_method,
  am.public_id,
  am.scope_id,
  am.name,
  am.description,
  am.create_time,
  am.update_time,
  am.version,
  am.state,
  am.api_url,
  am.disable_discovered_config_validation,
  am.issuer,
  am.client_id,
  am.client_secret,
  am.client_secret_hmac,
  am.key_id,
  am.max_age,
  -- the string_agg(..) column will be null if there are no associated value objects
  string_agg(distinct alg.signing_alg_name, '|') as algs,
  string_agg(distinct aud.aud_claim, '|') as auds,
  string_agg(distinct cert.certificate, '|') as certs,
  string_agg(distinct cs.scope, '|') as claims_scopes
from 	
  auth_oidc_method am 
  left outer join iam_scope               s     on am.public_id = s.primary_auth_method_id 
  left outer join auth_oidc_signing_alg   alg   on am.public_id = alg.oidc_method_id
  left outer join auth_oidc_aud_claim     aud   on am.public_id = aud.oidc_method_id
  left outer join auth_oidc_certificate   cert  on am.public_id = cert.oidc_method_id
  left outer join auth_oidc_scope         cs    on am.public_id = cs.oidc_method_id
group by am.public_id, is_primary_auth_method; -- there can be only one public_id + is_primary_auth_method, so group by isn't a problem.
comment on view oidc_auth_method_with_value_obj is
  'oidc auth method with its associated value objects (algs, auds, certs, scopes) as columns with | delimited values';

commit;
