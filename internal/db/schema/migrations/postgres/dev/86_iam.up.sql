begin;

-- iam_user_with_acct_info provides a consolidated view of users that includes
-- account info from the user scope's account info auth method
create view iam_user_with_acct_info as
select 
    u.public_id,
    u.scope_id,
    u.name,
    u.description, 
    u.create_time,
    u.update_time,
    u.version,
    oa.subject_id as login_name,
    oa.full_name as full_name,
    oa.email as email
from 	
    scope s
    auth_account aa
	auth_oidc_account oa
	iam_user u
where
	u.public_id = aa.iam_user_id and
    aa.public_id = oa.public_id and 
    aa.auth_method_id = s.account_info_auth_method_id 
union 
select 
    u.public_id,
    u.scope_id,
    u.name,
    u.description, 
    u.create_time,
    u.update_time,
    u.version,
    oa.subject_id as login_name,
    oa.full_name as full_name,
    oa.email as email
from 	
    scope s
    auth_account aa
	auth_password_account pa
	iam_user u
where
	u.public_id = aa.iam_user_id and
    aa.public_id = pa.public_id and 
    aa.auth_method_id = s.account_info_auth_method_id 


commit;