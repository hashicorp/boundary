begin;

-- add the account_info_auth_method_id which determines which auth_method is
-- designated as for "account info" in the user's scope.  
alter table iam_scope
add column account_info_auth_method_id wt_public_id -- allowed to be null and is mutable of course.
references auth_method(public_id)
on update cascade
on delete set null;

-- iam_user_acct_info provides account info for users by determining which
-- auth_method is designated as for "account info" in the user's scope via the
-- scope's account_info_auth_method_id.  Every sub-type of auth_account must be
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
    aa.auth_method_id = s.account_info_auth_method_id 
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
    aa.auth_method_id = s.account_info_auth_method_id;

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