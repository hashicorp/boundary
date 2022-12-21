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
  constraint auth_ldap_account_auth_method_id_public_id_uq
    unique(auth_method_id, public_id)
);
comment on table auth_ldap_account is 
'auth_ldap_account entries are subtypes of auth_account and represent an ldap account.';

create trigger insert_auth_account_subtype before insert on auth_ldap_account
  for each row execute procedure insert_auth_account_subtype();

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
  ('auth_ldap_account', 1);
  

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
  -- the string_agg(..) column will be null if there are no associated value objects
  string_agg(distinct url.url, '|') as urls,
  string_agg(distinct cert.certificate, '|') as certs,

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
  left outer join iam_scope                     s     on am.public_id = s.primary_auth_method_id 
  left outer join auth_ldap_url                 url   on am.public_id = url.ldap_method_id
  left outer join auth_ldap_certificate         cert  on am.public_id = cert.ldap_method_id
  left outer join auth_ldap_user_entry_search   uc    on am.public_id = uc.ldap_method_id
  left outer join auth_ldap_group_entry_search  gc    on am.public_id = gc.ldap_method_id
  left outer join auth_ldap_client_certificate  cc    on am.public_id = cc.ldap_method_id
  left outer join auth_ldap_bind_credential     bc    on am.public_id = bc.ldap_method_id
group by am.public_id, is_primary_auth_method; -- there can be only one public_id + is_primary_auth_method, so group by isn't a problem.
comment on view ldap_auth_method_with_value_obj is
  'ldap auth method with its associated value objects (urls, certs, search config, etc)';

commit;