-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- auth_oidc_method_state_enum entries define the possible oidc auth method
-- states. 
create table auth_oidc_method_state_enm (
  name text primary key
    constraint name_only_predefined_oidc_method_states_allowed
    check (
        name in ('inactive', 'active-private', 'active-public')
    )
);

-- populate the values of auth_oidc_method_state_enm
insert into auth_oidc_method_state_enm(name)
  values
    ('inactive'),
    ('active-private'),
    ('active-public');

 -- define the immutable fields for auth_oidc_method_state_enm (all of them)
create trigger immutable_columns before update on auth_oidc_method_state_enm
  for each row execute procedure immutable_columns('name');


-- auth_oidc_signing_alg entries define the supported oidc auth method
-- signing algorithms.
create table auth_oidc_signing_alg_enm (
  name text primary key
    constraint only_predefined_auth_oidc_signing_algs_allowed
    check (
        name in (
          'RS256', 
          'RS384', 
          'RS512', 
          'ES256', 
          'ES384', 
          'ES512', 
          'PS256', 
          'PS384', 
          'PS512', 
          'EdDSA')
    )
);

-- populate the values of auth_oidc_signing_alg
insert into auth_oidc_signing_alg_enm (name)
  values
    ('RS256'),
    ('RS384'),
    ('RS512'),
    ('ES256'),
    ('ES384'),
    ('ES512'),
    ('PS256'),
    ('PS384'),
    ('PS512'),
    ('EdDSA')
    ; 

 -- define the immutable fields for auth_oidc_signing_alg (all of them)
create trigger immutable_columns before update on auth_oidc_signing_alg_enm
  for each row execute procedure immutable_columns('name');

commit;
