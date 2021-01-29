begin;

-- auth_oidc_method entries are the current oidc auth methods configured for
-- existing scopes. 
create table auth_oidc_method (
  public_id wt_public_id
    primary key,
  scope_id wt_scope_id
    not null,
  name wt_name,
  description wt_description, 
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  state text not null
    references auth_oidc_method_state_enm(name)
    on delete restrict
    on update cascade,
  discovery_url wt_url not null, -- oidc discovery URL without any .well-known component
  client_id text not null -- oidc client identifier issued by the oidc provider.
    constraint client_id_not_empty
    check(length(trim(client_id)) > 0), 
  client_secret bytea not null, -- encrypted oidc client secret issued by the oidc provider.
  client_secret_hmac text not null
    constraint client_secret_hmac_not_empty
    check(length(trim(client_secret_hmac)) > 0),
  key_id wt_private_id not null -- key used to encrypt entries via wrapping wrapper. 
    references kms_database_key_version(private_id) 
    on delete restrict
    on update cascade, 
  max_age int  -- the allowable elapsed time in secs since the last time the user was authenticated. zero is allowed and should force the user to be re-authenticated.
    constraint max_age_not_equal_zero
    check(max_age != 0), 
  foreign key (scope_id, public_id)
      references auth_method (scope_id, public_id)
      on delete cascade
      on update cascade,
  unique(scope_id, name),
  unique(scope_id, public_id),
  unique(scope_id, discovery_url, client_id) -- a client_id must be unique for a provider within a scope.
);

-- auth_oidc_signing_alg entries are the signing algorithms allowed for an oidc
-- auth method.  There must be at least one allowed alg for each oidc auth method.
create table auth_oidc_signing_alg (
  oidc_method_id wt_public_id 
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  signing_alg_name text 
    references auth_oidc_signing_alg_enm(name)
    on delete restrict
    on update cascade,
  primary key(oidc_method_id, signing_alg_name)
);

-- auth_oidc_callback_url entries are the callback URLs allowed for a specific
-- oidc auth method.  There must be at least one callback url for each oidc auth
-- method. 
create table auth_oidc_callback_url (
  oidc_method_id wt_public_id 
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  callback_url wt_url not null
);

-- auth_oidc_aud_claim entries are the audience claims for a specific oidc auth
-- method.  There can be 0 or more for each parent oidc auth method.  If an auth
-- method has any aud claims, an ID token must contain one of them to be valid. 
create table auth_oidc_aud_claim (
  oidc_method_id wt_public_id 
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  aud_claim text not null
    constraint aud_claim_must_not_be_empty
    check(length(trim(aud_claim)) > 0) 
    constraint aud_claim_must_be_less_than_1024_chars
      check(length(trim(aud_claim)) < 1024),
  primary key(oidc_method_id, aud_claim)
);

-- auth_oidc_certificate entries are optional PEM encoded x509 certificates.
-- Each entry is a single certificate.  An oidc auth method may have 0 or more
-- of these optional x509s.  If an auth method has any cert entries, they are
-- used as trust anchors when connecting to the auth method's oidc provider
-- (instead of the host system's cert chain).
create table auth_oidc_certificate (
  oidc_method_id wt_public_id 
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  certificate bytea not null,
  primary key(oidc_method_id, certificate)
);


create table auth_oidc_account (
    public_id wt_public_id
      primary key,
    auth_method_id wt_public_id
      not null,
    -- NOTE(mgaffney): The scope_id type is not wt_scope_id because the domain
    -- check is executed before the insert trigger which retrieves the scope_id
    -- causing an insert to fail.
    scope_id text not null,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    issuer_id wt_url not null, -- case-sensitive URL that maps to an id_token's iss claim
    subject_id text not null -- case-senstive string that maps to an id_token's sub claim
      constraint subject_id_must_not_be_empty 
      check (
        length(trim(subject_id)) > 0
      )
      constraint subject_id_must_be_less_than_256_chars 
      check(
        length(trim(subject_id)) <= 255 -- length limit per OIDC spec
      ),
    full_name wt_full_name, -- may be null and maps to an id_token's name claim
    email wt_email, -- may be null and maps to the id_token's email claim
    foreign key (scope_id, auth_method_id)
      references auth_oidc_method (scope_id, public_id)
      on delete cascade
      on update cascade,
    foreign key (scope_id, auth_method_id, public_id)
      references auth_account (scope_id, auth_method_id, public_id)
      on delete cascade
      on update cascade,
    unique(auth_method_id, name),
    unique(auth_method_id, issuer_id, subject_id), -- subject must be unique for a provider within specific auth method
    unique(auth_method_id, public_id)
);

-- auth_oidc_method column triggers
create trigger
  insert_auth_method_subtype
before insert on auth_oidc_method
  for each row execute procedure insert_auth_method_subtype();

create trigger
  update_time_column
before
update on auth_oidc_method
  for each row execute procedure update_time_column();

create trigger
  immutable_columns
before
update on auth_oidc_method
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger
  default_create_time_column
before
insert on auth_oidc_method
  for each row execute procedure default_create_time();

create trigger
  update_version_column
after update on auth_oidc_method
  for each row execute procedure update_version_column();

-- auth_oidc_account column triggers
create trigger
  update_time_column
before
update on auth_oidc_account
  for each row execute procedure update_time_column();

create trigger
  immutable_columns
before
update on auth_oidc_account
  for each row execute procedure immutable_columns('public_id', 'auth_method_id', 'scope_id', 'create_time', 'issuer_id', 'subject_id');

create trigger
  default_create_time_column
before
insert on auth_oidc_account
  for each row execute procedure default_create_time();

create trigger
  update_version_column
after update on auth_oidc_account
  for each row execute procedure update_version_column();

create trigger
  insert_auth_account_subtype
before insert on auth_oidc_account
  for each row execute procedure insert_auth_account_subtype();

commit;
