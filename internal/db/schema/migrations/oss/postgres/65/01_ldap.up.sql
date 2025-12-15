-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table auth_ldap_method_state_enm (
  name text primary key
    constraint name_only_predefined_ldap_method_states_allowed
      check (name in ('inactive', 'active-private', 'active-public'))
);
comment on table auth_ldap_method_state_enm is 
'auth_ldap_method_state_enm entries enumerate the valid auth ldap method states';

-- populate the values of auth_ldap_method_state_enm
insert into auth_ldap_method_state_enm(name)
  values
    ('inactive'),
    ('active-private'),
    ('active-public');

-- column added to auth_ldap_method in in 76/01_ldap.up.sql
create table auth_ldap_method (
  public_id wt_public_id primary key,
  scope_id wt_scope_id not null,
  name wt_name,
  description wt_description,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  state text not null
    constraint auth_ldap_method_state_enm_fkey
      references auth_ldap_method_state_enm(name)
      on delete restrict
      on update cascade,
  start_tls bool not null default false,
  insecure_tls bool not null default false,
  discover_dn bool not null default false,
  anon_group_search bool not null default false,
  upn_domain text
    constraint upn_domain_too_short
      check (length(trim(upn_domain)) > 0)
    constraint upn_domain_too_long
      check (length(trim(upn_domain)) < 253),
  enable_groups bool not null default false,
  use_token_groups bool not null default false,
  constraint auth_method_fkey
    foreign key (scope_id, public_id)
    references auth_method (scope_id, public_id)
    on delete cascade
    on update cascade,
  constraint auth_ldap_method_scope_id_name_uq
    unique(scope_id, name),
  constraint auth_ldap_method_scope_id_public_id_uq
    unique(scope_id, public_id)
);
comment on table auth_ldap_method is
'auth_ldap_method entries are the current ldap auth methods configured for '
'existing scopes';

-- auth_ldap_method column triggers
create trigger insert_auth_method_subtype before insert on auth_ldap_method
  for each row execute procedure insert_auth_method_subtype();

create trigger delete_auth_method_subtype after delete on auth_ldap_method
  for each row execute procedure delete_auth_method_subtype();

create trigger update_auth_method_subtype before update on auth_ldap_method
  for each row execute procedure update_auth_method_subtype();

create trigger update_time_column before update on auth_ldap_method
  for each row execute procedure update_time_column();

create trigger immutable_columns before update on auth_ldap_method
  for each row execute procedure immutable_columns('public_id', 'scope_id', 'create_time');

create trigger default_create_time_column before insert on auth_ldap_method
  for each row execute procedure default_create_time();

create trigger update_version_column after update on auth_ldap_method
  for each row execute procedure update_version_column();

-- auth_ldap_url entries are LDAP URLs that specify an LDAP servers to connect
-- to. Examples: ldap://ldap.myorg.com, ldaps://ldap.myorg.com:636. There must
-- be at least one and if there's more than one URL configured for an auth
-- method, the directories will be tried in connection_priority order if there
-- are errors during the connection process.  The URL scheme must be either ldap
-- or ldaps. The port is optional.If no port is specified, then a default of 389
-- is used for ldap and a default of 689 is used for ldaps. (see rfc4516 for
-- more information about LDAP URLs)  
--
-- Updates will be implemented as a delete + insert with the auth_ldap_method
-- being used as the root aggregate for auth_ldap_url updates. 
create table auth_ldap_url ( 
  create_time wt_timestamp,
  ldap_method_id wt_public_id not null  
    constraint auth_ldap_method_fkey
      references auth_ldap_method(public_id)
      on delete cascade
      on update cascade,
  url text not null
    constraint url_too_short
        check (length(trim(url)) > 3)
    constraint url_too_long
        check (length(trim(url)) < 4000),
    constraint url_invalid_protocol
        check (url ~ 'ldaps?:\/\/*'),
  connection_priority int not null
    constraint connection_priority_less_than_one
      check(connection_priority >= 1),
  primary key(ldap_method_id, connection_priority)
);
comment on table auth_ldap_url is
'auth_ldap_url entries specify a connection URL an LDAP';

create function auth_ldap_url_parent_children() returns trigger 
as $$
declare 
  n integer;
begin
  if tg_op = 'INSERT' or tg_op = 'UPDATE' then 
    select into n count(*) from auth_ldap_url where ldap_method_id = new.ldap_method_id;
    if n < 1 then 
      raise exception 'During % of auth_ldap_url: auth_ldap_method id=% must have at least one url, not %',tg_op,new.ldap_method_id,n;
    end if;
  end if;
  if tg_op = 'UPDATE' then 
      select into n count(*) from auth_ldap_url where ldap_method_id = old.ldap_method_id;
      if n < 1 then 
        raise exception 'During % of %: auth_ldap_method id=% must have at least one url, not %',tg_op,tg_table_name,old.ldap_method_id,n;
      end if;
  end if;

  return null;
end;
$$ language plpgsql;
comment on function auth_ldap_url_parent_children() is 
'function used on auth_ldap_url after insert/update initially deferred to ensure each '
'auth_ldap_method has at least one auth_ldap_url. Unfortunately, it cannot be used on '
'delete since that would make it impossible to delete an ldap auth method, because you '
'would not be able to remove all of its urls';

create constraint trigger auth_ldap_url_children_per_parent_tg
  after insert or update or delete on auth_ldap_url deferrable initially deferred 
  for each row execute procedure auth_ldap_url_parent_children();

create function auth_ldap_method_children() returns trigger 
as $$
declare
  n integer;
begin
  if tg_op = 'INSERT' then 
    select into n count(*) from auth_ldap_url where ldap_method_id = new.public_id;
     if n < 1 then 
      raise exception 'During % of auth_ldap_method public_id=% must have at least one url, not %',tg_op,new.public_id,n;
    end if;
    -- No need for an UPDATE or DELETE check, as regular referential integrity constraints
    -- and the trigger on `child' will do the job.

    return null;
  end if;
end;
$$ language plpgsql;
comment on function auth_ldap_method_children() is 
'function used on auth_ldap_method after insert initially deferred to ensure each '
'auth_ldap_method has at least one auth_ldap_url';

create constraint trigger auth_ldap_method_children_tg
  after insert on auth_ldap_method deferrable initially deferred 
  for each row execute procedure auth_ldap_method_children();

-- auth_ldap_user_entry_search entries specify the required parameters to find a
-- user entry before attempting to authenticate the user.
--
-- Updates will be implemented as a delete + insert with the auth_ldap_method
-- being used as the root aggregate for auth_ldap_user_entry_search updates.
create table auth_ldap_user_entry_search (
  create_time wt_timestamp,
  ldap_method_id wt_public_id primary key
    constraint auth_ldap_method_fkey
      references auth_ldap_method(public_id)
      on delete cascade
      on update cascade,
  user_dn text
    constraint user_dn_too_short 
      check (length(trim(user_dn)) > 0)
    constraint user_dn_too_long
      check (length(trim(user_dn)) < 1025),
  user_attr text
    constraint user_attr_too_short
      check (length(trim(user_attr)) > 0)
    constraint user_attr_too_long
      check (length(trim(user_attr)) < 1025),
  user_filter text
    constraint user_filter_too_short
      check (length(trim(user_filter)) > 0)
    constraint user_filter_too_long
      check (length(trim(user_filter)) < 2049),
  constraint all_fields_are_not_null
    check (
      not(user_dn, user_attr, user_filter) is null
    )
);
comment on table auth_ldap_user_entry_search is 
'auth_ldap_user_entry_search entries specify the required parameters to find '
'a user entry before attempting to authenticate the user';

-- auth_ldap_group_entry_search entries specify the required parameters to find
-- the groups a user is a member of
--
-- Updates will be implemented as a delete + insert with the auth_ldap_method
-- being used as the root aggregate for auth_ldap_user_entry_search updates.
create table auth_ldap_group_entry_search (
  create_time wt_timestamp,
  ldap_method_id wt_public_id primary key
    constraint auth_ldap_method_fkey
      references auth_ldap_method(public_id)
      on delete cascade
      on update cascade,
  group_dn text not null -- required
    constraint group_dn_too_short 
      check (length(trim(group_dn)) > 0)
    constraint group_dn_too_long
      check (length(trim(group_dn)) < 1025),
  group_attr text
    constraint group_attr_too_short 
      check (length(trim(group_attr)) > 0)
    constraint group_attr_too_long
      check (length(trim(group_attr)) < 1025),
  group_filter text
    constraint group_filter_too_short
      check (length(trim(group_filter)) > 0)
    constraint group_filter_too_long
      check (length(trim(group_filter)) < 2049)
);
comment on table auth_ldap_group_entry_search is 
'auth_ldap_group_entry_search entries specify the required parameters to find '
'the groups a user is a member of';

create function auth_ldap_method_group_search() returns trigger 
as $$
declare
  n integer;
begin
  if new.enable_groups = true and  new.use_token_groups = false then 
    select into n count(*) from auth_ldap_group_entry_search where ldap_method_id = new.public_id;
    if n < 1 then
      raise exception 'During % of auth_ldap_method public_id=% must have a configured group_dn when enable_groups = true and use_token_groups = false',tg_op,new.public_id;
    end if;
  end if;
  return null;
end;
$$ language plpgsql;
comment on function auth_ldap_method_children() is 
'function used on auth_ldap_method after insert/update initially deferred to ensure each '
'groups search is properly configured when enable_groups is true and use_token_groups is false';

create constraint trigger auth_ldap_method_group_search
  after insert or update on auth_ldap_method deferrable initially deferred 
  for each row execute procedure auth_ldap_method_group_search();

-- auth_ldap_certificate entries are optional PEM encoded x509 certificates.
-- Each entry is a single certificate.  An ldap auth method may have 0 or more
-- of these optional x509s.  If an auth method has any cert entries, they are
-- used as trust anchors when connecting to the auth method's ldap provider
-- (instead of the host system's cert chain).
create table auth_ldap_certificate (
  create_time wt_timestamp,
  ldap_method_id wt_public_id not null
    constraint auth_ldap_method_fkey
      references auth_ldap_method(public_id)
      on delete cascade
      on update cascade,
  certificate bytea not null
    constraint certificate_must_not_be_empty
      check(length(certificate) > 0),
  primary key(ldap_method_id, certificate)
);
comment on table auth_ldap_certificate is
  'auth_ldap_certificate entries are optional PEM encoded x509 certificates. '
  'Each entry is a single certificate.  An ldap auth method may have 0 or more '
  'of these optional x509s.  If an auth method has any cert entries, they are '
  'used as trust anchors when connecting to the auth methods ldap provider '
  '(instead of the host system cert chain)';

create table auth_ldap_client_certificate (
  create_time wt_timestamp,
  ldap_method_id wt_public_id primary key
    constraint auth_ldap_method_fkey
      references auth_ldap_method (public_id)
      on delete cascade
      on update cascade,
  certificate bytea not null -- PEM encoded certificate
    constraint certificate_must_not_be_empty
      check(length(certificate) > 0),
  certificate_key bytea not null -- encrypted PEM encoded private key for certificate
    constraint certificate_key_must_not_be_empty
      check(length(certificate_key) > 0),
  certificate_key_hmac bytea not null
      constraint certificate_key_hmac_must_not_be_empty
          check(length(certificate_key_hmac) > 0),
  key_id text not null
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade
  );
  comment on table auth_ldap_client_certificate is
    'auth_ldap_client_certificate entries contains a client certificate that a '
    'auth_ldap_method uses for mTLS when connecting to an LDAP server. '
    'An auth_ldap_method can have 0 or 1 client certificates.';

create table auth_ldap_bind_credential (
  create_time wt_timestamp,
  ldap_method_id wt_public_id primary key
    constraint auth_ldap_method_fkey
      references auth_ldap_method (public_id)
      on delete cascade
      on update cascade,
  dn text not null
    constraint dn_too_short
      check (length(trim(dn)) > 0)
    constraint dn_too_long
      check (length(trim(dn)) < 2049),
  password bytea not null
    constraint password_not_empty
    check(length(password) > 0), -- encrypted password0
  password_hmac bytea not null
    constraint password_hmac_not_empty
    check(length(password_hmac) > 0),
  key_id text not null
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade
);
comment on table auth_ldap_bind_credential is 
'auth_ldap_bind_credential entries allow Boundary to bind (aka authenticate) using '
'the provided credentials when searching for the user entry used to authenticate.';

-- auth_ldap_account_attribute_map entries are the optional attribute maps from custom
-- attributes to the standard attribute of fullname and email.  There can be 0 or more
-- for each parent ldap auth method. 
create table auth_ldap_account_attribute_map (
  create_time wt_timestamp,
  ldap_method_id wt_public_id 
    constraint auth_ldap_method_fkey
    references auth_ldap_method(public_id)
    on delete cascade
    on update cascade,
  from_attribute text not null
    constraint from_attribute_must_not_be_empty
       check(length(trim(from_attribute)) > 0) 
    constraint from_attribute_must_be_less_than_1024_chars
      check(length(trim(from_attribute)) < 1024),
  to_attribute text not null 
    constraint to_attribute_valid_values 
      check (lower(to_attribute) in ('fullname', 'email')), -- intentionally case-sensitive matching
  primary key(ldap_method_id, to_attribute)
);
comment on table auth_ldap_account_attribute_map is
  'auth_ldap_account_attribute_map entries are the optional attribute maps from custom attributes to '
  'the standard attributes of sub, name and email.  There can be 0 or more for each parent ldap auth method.';

create trigger default_create_time_column before insert on auth_ldap_account_attribute_map
  for each row execute procedure default_create_time();

create trigger immutable_columns before update on auth_ldap_account_attribute_map
  for each row execute procedure immutable_columns('ldap_method_id', 'from_attribute', 'to_attribute', 'create_time');

create table auth_ldap_account (
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
  login_name text not null
    constraint login_name_must_be_lowercase
      check(lower(trim(login_name)) = login_name)
    constraint login_name_must_not_be_empty
      check(length(trim(login_name)) > 0),
  email wt_email, 
  full_name wt_full_name, 
  dn text -- will be null until the first successful authentication
    constraint dn_must_not_be_empty
      check(length(trim(dn)) > 0), 
  member_of_groups jsonb -- will be null until the first successful authentication
    constraint member_of_groups_must_not_be_empty
      check(length(trim(member_of_groups::text)) > 0),
  constraint auth_ldap_method_fkey
    foreign key (scope_id, auth_method_id)
      references auth_ldap_method (scope_id, public_id)
      on delete cascade
      on update cascade,
  constraint auth_account_fkey
    foreign key (scope_id, auth_method_id, public_id)
      references auth_account (scope_id, auth_method_id, public_id)
      on delete cascade
      on update cascade,
  constraint auth_ldap_account_auth_method_id_name_uq
    unique(auth_method_id, name),
  constraint auth_ldap_account_auth_method_id_login_name_uq
    unique(auth_method_id, login_name),
  constraint auth_ldap_account_auth_method_id_dn_uq
    unique(auth_method_id, dn),
  constraint auth_ldap_account_auth_method_id_public_id_uq
    unique(auth_method_id, public_id)
);
comment on table auth_ldap_account is 
'auth_ldap_account entries are subtypes of auth_account and represent an ldap account.';
  
-- insert_auth_ldap_account_subtype is intended as a before insert
-- trigger on auth_ldap_account. Its purpose is to insert a base
-- auth_account for new ldap accounts.  It's a bit different than the
-- standard trigger for this, because it will have conflicting PKs
-- and we just want to "do nothing" on those conflicts, deferring the
-- raising on an error to insert into the auth_ldap_account table.
-- this is all necessary because of we're using predictable public ids
-- for ldap accounts.
create or replace function insert_auth_ldap_account_subtype() returns trigger
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

create trigger insert_auth_ldap_account_subtype before insert on auth_ldap_account
  for each row execute procedure insert_auth_ldap_account_subtype();

create trigger delete_auth_account_subtype after delete on auth_ldap_account
    for each row execute procedure delete_auth_account_subtype();

create trigger update_time_column before update on auth_ldap_account
  for each row execute procedure update_time_column();

create trigger immutable_columns before update on auth_ldap_account
  for each row execute procedure immutable_columns('public_id', 'auth_method_id', 'scope_id', 'create_time', 'login_name');

create trigger default_create_time_column before insert on auth_ldap_account
  for each row execute procedure default_create_time();

create trigger update_version_column after update on auth_ldap_account
  for each row execute procedure update_version_column();


insert into oplog_ticket (name, version)
values
  ('auth_ldap_method', 1), -- auth_ldap_method is the root aggregate itself and all of its value objects.
  ('auth_ldap_account', 1),
  ('auth_ldap_managed_group', 1);
  

-- updated in 76/01_ldap.up.sql
-- ldap_auth_method_with_value_obj is useful for reading an ldap auth method 
-- with its associated value objects (urls, certs, search config, etc). The use
-- of the postgres string_agg(...) to aggregate the url and cert value objects
-- into a column works because we are only pulling in one column from the
-- associated tables and that value is part of the primary key and unique.  This
-- view will make things like recursive listing of ldap auth methods fairly
-- straightforward to implement for the ldap repo.  The view also includes an
-- is_primary_auth_method bool 
create view ldap_auth_method_with_value_obj as 
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
  am.start_tls,
  am.insecure_tls,
  am.discover_dn,
  am.anon_group_search,
  am.upn_domain,
  am.enable_groups,
  am.use_token_groups,
  -- the string_agg(..) column will be null if there are no associated value objects
  string_agg(distinct url.url, '|') as urls,
  string_agg(distinct cert.certificate, '|') as certs,
  string_agg(distinct concat_ws('=', aam.from_attribute, aam.to_attribute), '|') as account_attribute_map,
  
  -- the rest of the fields are zero to one relationships that are stored in
  -- related tables. Since we're outer joining with these tables, we need to
  -- either add them to the group by, use an aggregating func, or handle
  -- multiple rows returning for each auth method. I've chosen to just use
  -- string_agg(...) 
  string_agg(distinct uc.user_dn, '|') as user_dn, 
  string_agg(distinct uc.user_attr, '|') as user_attr, 
  string_agg(distinct uc.user_filter, '|') as user_filter, 
  string_agg(distinct gc.group_dn, '|') as group_dn, 
  string_agg(distinct gc.group_attr, '|') as group_attr, 
  string_agg(distinct gc.group_filter, '|') as group_filter, 
  string_agg(distinct cc.certificate_key, '|') as client_certificate_key, 
  string_agg(distinct cc.certificate_key_hmac, '|') as client_certificate_key_hmac, 
  string_agg(distinct cc.key_id, '|') as client_certificate_key_id, 
  string_agg(distinct cc.certificate, '|') as client_certificate_cert,
  string_agg(distinct bc.dn, '|') as bind_dn, 
  string_agg(distinct bc.password, '|') as bind_password, 
  string_agg(distinct bc.password_hmac, '|') as bind_password_hmac,
  string_agg(distinct bc.key_id, '|') as bind_password_key_id 
from 	
  auth_ldap_method am 
  left outer join iam_scope                       s     on am.public_id = s.primary_auth_method_id 
  left outer join auth_ldap_url                   url   on am.public_id = url.ldap_method_id
  left outer join auth_ldap_certificate           cert  on am.public_id = cert.ldap_method_id
  left outer join auth_ldap_account_attribute_map aam   on am.public_id = aam.ldap_method_id
  left outer join auth_ldap_user_entry_search     uc    on am.public_id = uc.ldap_method_id
  left outer join auth_ldap_group_entry_search    gc    on am.public_id = gc.ldap_method_id
  left outer join auth_ldap_client_certificate    cc    on am.public_id = cc.ldap_method_id
  left outer join auth_ldap_bind_credential       bc    on am.public_id = bc.ldap_method_id
group by am.public_id, is_primary_auth_method; -- there can be only one public_id + is_primary_auth_method, so group by isn't a problem.
comment on view ldap_auth_method_with_value_obj is
  'ldap auth method with its associated value objects (urls, certs, search config, etc)';

create table auth_ldap_managed_group (
  public_id wt_public_id primary key,
  auth_method_id wt_public_id not null,
  name wt_name,
  description wt_description,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version wt_version,
  group_names jsonb not null 
    constraint group_names_must_not_be_empty
      check(length(trim(group_names::text)) > 0),
  constraint auth_ldap_method_fkey
    foreign key (auth_method_id) -- fk1
      references auth_ldap_method (public_id)
      on delete cascade
      on update cascade,
  -- Ensure it relates to an abstract managed group
  constraint auth_managed_group_fkey
    foreign key (auth_method_id, public_id) -- fk2
      references auth_managed_group (auth_method_id, public_id)
      on delete cascade
      on update cascade,
  constraint auth_ldap_managed_group_auth_method_id_name_uq
    unique(auth_method_id, name)
);
comment on table auth_ldap_managed_group is
'auth_ldap_managed_group entries are subtypes of auth_managed_group and represent an ldap managed group.';

-- Define the immutable fields of auth_ldap_managed_group
create trigger immutable_columns before update on auth_ldap_managed_group
  for each row execute procedure immutable_columns('public_id', 'auth_method_id', 'create_time');

-- Populate create time on insert
create trigger default_create_time_column before insert on auth_ldap_managed_group
  for each row execute procedure default_create_time();

-- Generate update time on update
create trigger update_time_column before update on auth_ldap_managed_group
  for each row execute procedure update_time_column();

-- Update version when something changes
create trigger update_version_column after update on auth_ldap_managed_group
  for each row execute procedure update_version_column();

-- Add into the base table when inserting into the concrete table
create trigger insert_managed_group_subtype before insert on auth_ldap_managed_group
  for each row execute procedure insert_managed_group_subtype();

-- Ensure that deletions in the ldap subtype result in deletions to the base
-- table.
create trigger delete_managed_group_subtype after delete on auth_ldap_managed_group
  for each row execute procedure delete_managed_group_subtype();


-- auth_ldap_managed_group_member_account uses CTEs to expand and "normalize" the jsonb column
-- containing groups in both the accounts and managed groups, then it joins these
-- "normalized" expressions into a join table of mangagd group member account entries
create view auth_ldap_managed_group_member_account as
with
account(id, group_name) as (
	select 
    	a.public_id, ag.group_name
	from 
  		auth_ldap_account a
	left join jsonb_array_elements(a.member_of_groups) as ag(group_name) on true
),
groups (create_time, id, group_name) as (
	select 
    g.create_time,
		g.public_id,
    mg.group_name
	from 
		auth_ldap_managed_group g
	left join jsonb_array_elements(g.group_names) as mg(group_name) on true
)
select distinct 
  groups.create_time, 
  account.id as member_id, 
  groups.id as managed_group_id
from account, groups
where account.group_name = groups.group_name;
comment on view auth_ldap_managed_group_member_account is 
'auth_ldap_managed_group_member_account is the join view for '
'managed ldap groups and accounts';


-- recreate view defined in postgres/9/03_oidc_managed_group_member.up.sql 
-- so the new view can include both oidc and ldap managed groups
drop view auth_managed_group_member_account;

-- create view with both oidc and ldap managed groups; we can replace this view
-- to union with other subtype tables as needed in the future. 
create view auth_managed_group_member_account as
select
  oidc.create_time,
  oidc.managed_group_id,
  oidc.member_id
from
  auth_oidc_managed_group_member_account oidc
union
select 
  ldap.create_time,
  ldap.managed_group_id,
  ldap.member_id
from 
  auth_ldap_managed_group_member_account ldap;
comment on view auth_managed_group_member_account is 
'';

commit;