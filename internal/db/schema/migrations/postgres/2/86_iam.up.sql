begin;

-- add the primary_auth_method_id which determines which auth_method is
-- designated as for "account info" in the user's scope. It also determines
-- which auth method is allowed to auto viviify users.  
alter table iam_scope
add column primary_auth_method_id wt_public_id  -- allowed to be null and is mutable of course.
constraint auth_method_fkey
references auth_method(public_id)
    on update cascade
    on delete set null;

-- establish a compond fk, but there's no cascading of deletes or updates, since
-- we only want to cascade changes to the primary_auth_method_id portion of
-- the compond fk and that is handled in a separate fk declaration.
alter table iam_scope
add constraint auth_method
  foreign key (public_id, primary_auth_method_id) 
  references auth_method(scope_id, public_id); 


-- the intent of this update statement: set the primary auth method for scopes
-- that only have a single auth_password_method, since currently there are only
-- auth_password_methods in boundary. Before this release all
-- auth_password_methods were "basically" primary auth methods and would create
-- an iam_user on first login.
with single_authmethod (scope_id, public_id) as (
  select 
    am.scope_id, 
    am.public_id  
  from 
    auth_password_method am,
    (select 
        scope_id, 
        count(public_id) as cnt 
     from 
        auth_password_method 
     group by scope_id) as singles
    where 
      am.scope_id = singles.scope_id and
      singles.cnt = 1
)
update 
  iam_scope
set 
  primary_auth_method_id = p.public_id
from
  single_authmethod p
where p.scope_id = iam_scope.public_id;


with many_authmethod (scope_id, authmethod_cnt) as (
  select 
    am.scope_id, 
    many.cnt
  from 
    auth_password_method am,
    (select 
        scope_id, 
        count(public_id) as cnt 
     from 
        auth_password_method 
     group by scope_id) as many
    where 
      am.scope_id = many.scope_id and
      many.cnt > 1
)
insert into log_migration(entry) 
select 
  concat(
      'unable to set primary_auth_method for ', 
      scope_id, 
      ' there were ', 
      m.authmethod_cnt, 
      ' password auth methods for that scope.'
  ) as entry
from
  iam_scope s,
  many_authmethod m
where 
  s.primary_auth_method_id = null and 
  s.public_id = m.scope_id;

-- iam_user_acct_info provides account info for users by determining which
-- auth_method is designated as for "account info" in the user's scope via the
-- scope's primary_auth_method_id.  Every sub-type of auth_account must be
-- added to this view's union.
create view iam_acct_info as
select 
    aa.iam_user_id,
    oa.subject_id as login_name,
    oa.full_name as full_name,
    oa.email as email
from 	
    iam_scope s,
    auth_account aa,
    auth_oidc_account oa
where
    aa.public_id = oa.public_id and 
    aa.auth_method_id = s.primary_auth_method_id 
union 
select 
    aa.iam_user_id,
    pa.login_name,
    '' as full_name,
    '' as email
from 	
    iam_scope s,
    auth_account aa,
    auth_password_account pa
where
    aa.public_id = pa.public_id and 
    aa.auth_method_id = s.primary_auth_method_id;

-- iam_user_acct_info provides a simple way to retrieve entries that include
-- both the iam_user fields with an outer join to the user's account info.
create view iam_user_acct_info as
select 
    u.public_id,
    u.scope_id,
    u.name,
    u.description, 
    u.create_time,
    u.update_time,
    u.version,
    i.login_name,
    i.full_name,
    i.email
from 	
	iam_user u
left outer join iam_acct_info i on u.public_id = i.iam_user_id;

commit;