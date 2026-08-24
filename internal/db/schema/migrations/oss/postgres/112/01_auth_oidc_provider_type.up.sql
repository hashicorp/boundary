-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

-- Adds auth_oidc_method_provider_type_enm enum table and a nullable provider_type column
-- on auth_oidc_method to support Azure Entra ID group overage resolution. Recreates the
-- oidc_auth_method_with_value_obj view to include the new provider_type column.

begin;

-- auth_oidc_method_provider_type_enm entries define the supported oidc auth method provider types.
create table auth_oidc_method_provider_type_enm (
  name text primary key
    constraint only_predefined_auth_oidc_provider_types_allowed
      check (
        name in (
          'azure'
        )
      )
);

comment on table auth_oidc_method_provider_type_enm is
  'auth_oidc_method_provider_type_enm entries enumerate the valid oidc auth method provider types';

-- define the immutable fields for auth_oidc_method_provider_type_enm
create trigger immutable_columns before update on auth_oidc_method_provider_type_enm
  for each row execute procedure immutable_columns('name');

insert into auth_oidc_method_provider_type_enm (name) 
values
  ('azure');

-- add an optional provider_type column to auth_oidc_method. null means the
-- provider type is unspecified and no provider-specific behavior is applied.
alter table auth_oidc_method
  add column provider_type text
    constraint auth_oidc_method_provider_type_enm_fkey
      references auth_oidc_method_provider_type_enm(name)
      on delete restrict
      on update cascade;

-- we will drop the oidc_auth_method_with_value_obj view, so we can recreate it
-- and add the provider_type to the returned set.
drop view oidc_auth_method_with_value_obj;

-- Replaces view from 79/01_auth_oidc_prompt.up.sql
-- oidc_auth_method_with_value_obj is useful for reading an oidc auth method
-- with its associated value objects (algs, auds, certs, claims scopes,
-- account claim maps and prompts) as columns with | delimited values.  The
-- use of the postgres string_agg(...) to aggregate the value objects into a
-- column works because we are only pulling in one column from the associated
-- tables and that value is part of the primary key and unique.  This view
-- will make things like recursive listing of oidc auth methods fairly
-- straightforward to implement for the oidc repo. The view also includes an
-- is_primary_auth_method bool
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
  am.provider_type,
  -- the string_agg(..) column will be null if there are no associated value objects
  string_agg(distinct alg.signing_alg_name, '|') as algs,
  string_agg(distinct aud.aud_claim, '|') as auds,
  string_agg(distinct cert.certificate, '|') as certs,
  string_agg(distinct cs.scope, '|') as claims_scopes,
  string_agg(distinct p.prompt, '|') as prompts,
  string_agg(distinct concat_ws('=', acm.from_claim, acm.to_claim), '|') as account_claim_maps
from
  auth_oidc_method am
  left outer join iam_scope                   s     on am.public_id = s.primary_auth_method_id
  left outer join auth_oidc_signing_alg       alg   on am.public_id = alg.oidc_method_id
  left outer join auth_oidc_aud_claim         aud   on am.public_id = aud.oidc_method_id
  left outer join auth_oidc_certificate       cert  on am.public_id = cert.oidc_method_id
  left outer join auth_oidc_scope             cs    on am.public_id = cs.oidc_method_id
  left outer join auth_oidc_account_claim_map acm   on am.public_id = acm.oidc_method_id
  left outer join auth_oidc_prompt            p     on am.public_id = p.oidc_method_id
group by am.public_id, is_primary_auth_method; -- there can be only one public_id + is_primary_auth_method, so group by isn't a problem.
comment on view oidc_auth_method_with_value_obj is
  'oidc auth method with its associated value objects (algs, auds, certs, scopes, prompts) as columns with | delimited values';

commit;
