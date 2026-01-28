-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

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
  to_claim text not null 
    constraint to_claim_valid_values 
      check (to_claim in ('sub', 'name', 'email')), -- intentionally case-sensitive matching
  primary key(oidc_method_id, to_claim)
);
comment on table auth_oidc_account_claim_map is
  'auth_oidc_account_claim_map entries are the optional claim maps from custom claims to the standard claims of sub, name and email.  There can be 0 or more for each parent oidc auth method.';

create trigger default_create_time_column before insert on auth_oidc_account_claim_map
  for each row execute procedure default_create_time();

create trigger immutable_columns before update on auth_oidc_account_claim_map
  for each row execute procedure immutable_columns('oidc_method_id', 'from_claim', 'to_claim', 'create_time');
  

-- we will drop the oidc_auth_method_with_value_obj view, so we can recreate it
-- and add the oidc claim's scopes to the returned set.
drop view oidc_auth_method_with_value_obj;

-- oidc_auth_method_with_value_obj is useful for reading an oidc auth method
-- with its associated value objects (algs, auds, certs, claims scopes and
-- account claim maps) as columns with | delimited values.  The use of the
-- postgres string_agg(...) to aggregate the value objects into a column works
-- because we are only pulling in one column from the associated tables and that
-- value is part of the primary key and unique.  This view will make things like
-- recursive listing of oidc auth methods fairly straightforward to implement
-- for the oidc repo. The view also includes an is_primary_auth_method bool 
-- Recreated in 56/02_add_data_key_foreign_key_references.up.sql
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
  string_agg(distinct cs.scope, '|') as claims_scopes,
  string_agg(distinct concat_ws('=', acm.from_claim, acm.to_claim), '|') as account_claim_maps
from 	
  auth_oidc_method am 
  left outer join iam_scope                   s     on am.public_id = s.primary_auth_method_id 
  left outer join auth_oidc_signing_alg       alg   on am.public_id = alg.oidc_method_id
  left outer join auth_oidc_aud_claim         aud   on am.public_id = aud.oidc_method_id
  left outer join auth_oidc_certificate       cert  on am.public_id = cert.oidc_method_id
  left outer join auth_oidc_scope             cs    on am.public_id = cs.oidc_method_id
  left outer join auth_oidc_account_claim_map acm   on am.public_id = acm.oidc_method_id
group by am.public_id, is_primary_auth_method; -- there can be only one public_id + is_primary_auth_method, so group by isn't a problem.
comment on view oidc_auth_method_with_value_obj is
  'oidc auth method with its associated value objects (algs, auds, certs, scopes) as columns with | delimited values';

  
commit;
