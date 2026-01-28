-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- auth_oidc_method entries are the current oidc auth methods configured for
-- existing scopes. 
create table auth_oidc_method (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null,
  name wt_name,
  description wt_description,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  state text not null
    constraint auth_oidc_method_state_enm_fkey
      references auth_oidc_method_state_enm(name)
      on delete restrict
      on update cascade,
  disable_discovered_config_validation bool not null default false,
  api_url wt_url, -- an address prefix at which the boundary api is reachable.
  issuer wt_url,
  client_id text  -- oidc client identifier issued by the oidc provider.
    constraint client_id_not_empty
    check(length(trim(client_id)) > 0), 
  client_secret bytea, -- encrypted oidc client secret issued by the oidc provider.
  client_secret_hmac text 
    constraint client_secret_hmac_not_empty
    check(length(trim(client_secret_hmac)) > 0),
  key_id wt_private_id not null -- key used to encrypt entries via wrapping wrapper. 
    constraint kms_database_key_version_fkey
      references kms_database_key_version(private_id) 
      on delete restrict
      on update cascade, 
    constraint key_id_not_empty
      check(length(trim(key_id)) > 0),
  max_age int  -- the allowable elapsed time in secs since the last time the user was authenticated. A value -1 basically forces the IdP to re-authenticate the End-User.  Zero is not a valid value. 
    constraint max_age_not_equal_zero
      check(max_age != 0)
    constraint max_age_not_less_then_negative_one
      check(max_age >= -1), 
  constraint auth_method_fkey
    foreign key (scope_id, public_id)
        references auth_method (scope_id, public_id)
        on delete cascade
        on update cascade,
  constraint auth_oidc_method_scope_id_name_uq
    unique(scope_id, name),
  constraint auth_oidc_method_scope_id_public_id_uq
    unique(scope_id, public_id),
  constraint auth_oidc_method_scope_id_issuer_client_id_unique
    unique(scope_id, issuer, client_id) -- a client_id must be unique for a provider within a scope.
);
comment on table auth_oidc_method is
  'auth_oidc_method entries are the current oidc auth methods configured for existing scopes.';

-- auth_oidc_signing_alg entries are the signing algorithms allowed for an oidc
-- auth method.  There must be at least one allowed alg for each oidc auth method.
create table auth_oidc_signing_alg (
  create_time wt_timestamp,
  oidc_method_id wt_public_id 
    constraint auth_oidc_method_fkey
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  signing_alg_name text 
    constraint auth_oidc_signing_alg_enm_fkey
    references auth_oidc_signing_alg_enm(name)
    on delete restrict
    on update cascade,
  primary key(oidc_method_id, signing_alg_name)
);
comment on table auth_oidc_signing_alg is
  'auth_oidc_signing_alg entries are the signing algorithms allowed for an oidc auth method. There must be at least one allowed alg for each oidc auth method';

-- auth_oidc_aud_claim entries are the audience claims for a specific oidc auth
-- method.  There can be 0 or more for each parent oidc auth method.  If an auth
-- method has any aud claims, an ID token must contain one of them to be valid. 
create table auth_oidc_aud_claim (
  create_time wt_timestamp,
  oidc_method_id wt_public_id 
    constraint auth_oidc_method_fkey
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
comment on table auth_oidc_aud_claim is
  'auth_oidc_aud_claim entries are the audience claims for a specific oidc auth method.  There can be 0 or more for each parent oidc auth method.  If an auth method has any aud claims, an ID token must contain one of them to be valid.';


-- auth_oidc_certificate entries are optional PEM encoded x509 certificates.
-- Each entry is a single certificate.  An oidc auth method may have 0 or more
-- of these optional x509s.  If an auth method has any cert entries, they are
-- used as trust anchors when connecting to the auth method's oidc provider
-- (instead of the host system's cert chain).
create table auth_oidc_certificate (
  create_time wt_timestamp,
  oidc_method_id wt_public_id 
    constraint auth_oidc_method_fkey
    references auth_oidc_method(public_id)
    on delete cascade
    on update cascade,
  certificate bytea not null,
  primary key(oidc_method_id, certificate)
);
comment on table auth_oidc_certificate is
  'auth_oidc_certificate entries are optional PEM encoded x509 certificates. Each entry is a single certificate.  An oidc auth method may have 0 or more of these optional x509s.  If an auth method has any cert entries, they are used as trust anchors when connecting to the auth methods oidc provider (instead of the host system cert chain)';


-- auth_oidc_account entries are subtypes of auth_account and represent an
-- oidc account.
create table auth_oidc_account (
    public_id wt_public_id primary key,
    auth_method_id wt_public_id not null,
    -- NOTE(mgaffney): The scope_id type is not wt_scope_id because the domain
    -- check is executed before the insert trigger which retrieves the scope_id
    -- causing an insert to fail.
    scope_id text not null,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    issuer wt_url not null, -- case-sensitive URL that maps to an id_token's iss claim,
    subject text not null -- case-sensitive string that maps to an id_token's sub claim
      constraint subject_must_not_be_empty
      check (
        length(trim(subject)) > 0
      )
      constraint subject_must_be_less_than_256_chars
      check(
        length(trim(subject)) <= 255 -- length limit per OIDC spec
      ),
    full_name wt_full_name, -- may be null and maps to an id_token's name claim
    email wt_email, -- may be null and maps to the id_token's email claim
    constraint auth_oidc_method_fkey
      foreign key (scope_id, auth_method_id)
        references auth_oidc_method (scope_id, public_id)
        on delete cascade
        on update cascade,
    constraint auth_account_fkey
      foreign key (scope_id, auth_method_id, public_id)
        references auth_account (scope_id, auth_method_id, public_id)
        on delete cascade
        on update cascade,
    constraint auth_oidc_account_auth_method_id_name_uq
      unique(auth_method_id, name),
    -- ###############################################################
    -- any change to this constraints name must be aligned with the 
    -- acctUpsertQuery const in internal/auth/oidc/query.go
    -- ###############################################################
    constraint auth_oidc_account_auth_method_id_issuer_subject_uq
      unique(auth_method_id, issuer, subject), -- subject must be unique for a provider within specific auth method
    constraint auth_oidc_account_auth_method_id_public_id_uq
      unique(auth_method_id, public_id)
);
-- Comment fixed in 58/01_fix_comments.up.sql
comment on table auth_oidc_method is
  'auth_oidc_account entries are subtypes of auth_account and represent an oidc account.';

-- auth_oidc_method column triggers
create trigger insert_auth_method_subtype before insert on auth_oidc_method
  for each row execute procedure insert_auth_method_subtype();

create trigger update_time_column before update on auth_oidc_method
  for each row execute procedure update_time_column();

create trigger immutable_columns before update on auth_oidc_method
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger default_create_time_column before insert on auth_oidc_method
  for each row execute procedure default_create_time();

create trigger update_version_column after update on auth_oidc_method
  for each row execute procedure update_version_column();

-- active_auth_oidc_method_must_be_complete() defines a function to be used in 
-- a "before update" trigger for auth_oidc_method entries.  Its intent: prevent
-- incomplete oidc methods from transitioning out of the "inactive" state.
create or replace function active_auth_oidc_method_must_be_complete() returns trigger
as $$
  begin
    -- validate signing alg
    if old.state = 'inactive' and new.state != 'inactive' then
      perform 
      from 
        auth_oidc_method am
       join auth_oidc_signing_alg alg on am.public_id = alg.oidc_method_id
      where
        new.public_id = am.public_id;
      if not found then 
        raise exception 'an incomplete oidc auth method must remain inactive';
      end if;
      -- validate issuer
      case 
        when new.issuer != old.issuer then
          if length(trim(new.issuer)) = 0 then
            raise exception 'empty issuer: an incomplete oidc auth method must remain inactive';
          end if;
        when new.issuer = old.issuer then
          if length(trim(old.issuer)) = 0 then
            raise exception 'empty issuer: an incomplete oidc auth method must remain inactive';
          end if;
        else
      end case;
      -- validate client_id
      case 
        when new.client_id != old.client_id then
          if length(trim(new.client_id)) = 0 then
            raise exception 'empty client_id: an incomplete oidc auth method must remain inactive';
          end if;
        when new.client_id = old.client_id then
          if length(trim(old.client_id)) = 0 then
            raise exception 'empty client_id: an incomplete oidc auth method must remain inactive';
          end if;
        else
      end case;
      -- validate client_secret
      case 
        when new.client_secret != old.client_secret then
          if length(new.client_secret) = 0 then
            raise exception 'empty client_secret: an incomplete oidc auth method must remain inactive';
          end if;
        when new.client_secret = old.client_secret then
          if length(old.client_secret) = 0 then
            raise exception 'empty client_secret: an incomplete oidc auth method must remain inactive';
          end if;
        else
      end case;


    end if;
    return new;
  end;
$$ language plpgsql;
comment on function active_auth_oidc_method_must_be_complete() is
  'active_auth_oidc_method_must_be_complete() will raise an error if the oidc auth method is not complete';

create trigger update_active_auth_oidc_method_must_be_complete before update on auth_oidc_method
  for each row execute procedure active_auth_oidc_method_must_be_complete();

-- new_auth_oidc_method_must_be_inactive() defines a function to be used in 
-- a "before insert" trigger for auth_oidc_method entries.  Its intent: 
-- only allow "inactive" auth methods to be inserted.  Why? there's no way
-- you can insert an entry that's anything but incomplete, since we have a 
-- chicken/egg problem: you need the auth method id to create the required
-- signing algs value objects.
create or replace function new_auth_oidc_method_must_be_inactive() returns trigger
as $$
  begin
    if new.state != 'inactive' then
      raise exception 'an incomplete oidc method must be inactive';
    end if;
  end;
$$ language plpgsql;
comment on function new_auth_oidc_method_must_be_inactive() is
  'new_auth_oidc_method_must_be_inactive ensures that new incomplete oidc auth methods must remain inactive';

create trigger new_auth_oidc_method_must_be_inactive before insert on auth_oidc_method
  for each row execute procedure active_auth_oidc_method_must_be_complete();

-- auth_oidc_account column triggers
create trigger update_time_column before update on auth_oidc_account
  for each row execute procedure update_time_column();

create trigger immutable_columns before update on auth_oidc_account
  for each row execute procedure immutable_columns('public_id', 'auth_method_id', 'scope_id', 'create_time', 'issuer', 'subject');

create trigger default_create_time_column before insert on auth_oidc_account
  for each row execute procedure default_create_time();

create trigger update_version_column after update on auth_oidc_account
  for each row execute procedure update_version_column();


-- insert_auth_oidc_account_subtype is intended as a before insert
-- trigger on auth_oidc_account. Its purpose is to insert a base
-- auth_account for new oidc accounts.  It's a bit different than the
-- standard trigger for this, because it will have conflicting PKs
-- and we just want to "do nothing" on those conflicts, deferring the
-- raising on an error to insert into the auth_oidc_account table.
-- this is all necessary because of we're using predictable public ids
-- for oidc accounts.
create or replace function insert_auth_oidc_account_subtype() returns trigger
as $$
begin
  select auth_method.scope_id
    into new.scope_id
  from auth_method
  where auth_method.public_id = new.auth_method_id;

  insert into auth_account
    (public_id, auth_method_id, scope_id)
  values
    (new.public_id, new.auth_method_id, new.scope_id)
  on conflict do nothing;

  return new;
end;
  $$ language plpgsql;

create trigger insert_auth_oidc_account_subtype before insert on auth_oidc_account
  for each row execute procedure insert_auth_oidc_account_subtype();

-- triggers for auth_oidc_method children tables: auth_oidc_aud_claim,
-- auth_oidc_certificate, auth_oidc_signing_alg


-- on_delete_active_auth_oidc_method_must_be_complete() defines a function
-- to be used in an "after delete" trigger for auth_oidc_signing_alg
-- Its intent: prevent deletes that would result in an "active" oidc
-- auth method which is incomplete.
create or replace function on_delete_active_auth_oidc_method_must_be_complete() returns trigger
as $$
declare am_state text;
declare alg_cnt int;
  begin
    select 
      am.state,
      count(alg.oidc_method_id) as alg_cnt
    from
      auth_oidc_method am
      left outer join auth_oidc_signing_alg alg on am.public_id = alg.oidc_method_id
    where
      new.oidc_method_id = am.public_id
    group by am.public_id
    into am_state, alg_cnt;
    
    if not found then 
      return new; -- auth method was deleted, so we're done
    end if;

    if am_state != inactive then
      case 
        when alg_cnt = 0 then
          raise exception 'delete would have resulted in an incomplete active oidc auth method with no signing algorithms';
      end case;
    end if; 
  
    return new;
  end;
$$ language plpgsql;
comment on function on_delete_active_auth_oidc_method_must_be_complete() is
  'on_delete_active_auth_oidc_method_must_be_complete() will raise an error if the oidc auth method is not complete after a delete on algs';

create trigger
  default_create_time_column
before
insert on auth_oidc_aud_claim
  for each row execute procedure default_create_time();

create trigger
  default_create_time_column
before
insert on auth_oidc_certificate
  for each row execute procedure default_create_time();

create trigger
  default_create_time_column
before
insert on auth_oidc_signing_alg
  for each row execute procedure default_create_time();

create trigger on_delete_active_auth_oidc_method_must_be_complete after delete on auth_oidc_signing_alg
  for each row execute procedure on_delete_active_auth_oidc_method_must_be_complete();
    
insert into oplog_ticket (name, version)
values
  ('auth_oidc_method', 1), -- auth method is the root aggregate itself and all of its value objects.
  ('auth_oidc_account', 1);

commit;
