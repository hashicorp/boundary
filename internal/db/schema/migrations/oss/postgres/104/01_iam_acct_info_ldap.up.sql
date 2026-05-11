-- Copyright IBM Corp. 2026
-- SPDX-License-Identifier: BUSL-1.1

-- Replaces iam_acct_info and iam_user_acct_info from 4/01_iam.up.sql
-- Add auth_ldap_account to iam_acct_info so that LDAP users with a primary
-- LDAP auth method have their full_name and email surfaced through
-- iam_user_acct_info.

begin;

  drop view iam_user_acct_info;
  drop view iam_acct_info;

  create view iam_acct_info as
    select aa.iam_user_id,
           oa.subject     as login_name,
           oa.public_id   as primary_account_id,
           oa.full_name   as full_name,
           oa.email       as email
      from iam_scope s,
           auth_account aa,
           auth_oidc_account oa
     where aa.public_id = oa.public_id
       and aa.auth_method_id = s.primary_auth_method_id
     union
    select aa.iam_user_id,
           pa.login_name  as login_name,
           pa.public_id   as primary_account_id,
           ''             as full_name,
           ''             as email
      from iam_scope s,
           auth_account aa,
           auth_password_account pa
     where aa.public_id = pa.public_id
       and aa.auth_method_id = s.primary_auth_method_id
     union
    select aa.iam_user_id,
           la.login_name  as login_name,
           la.public_id   as primary_account_id,
           la.full_name   as full_name,
           la.email       as email
      from iam_scope s,
           auth_account aa,
           auth_ldap_account la
     where aa.public_id = la.public_id
       and aa.auth_method_id = s.primary_auth_method_id;

  create view iam_user_acct_info as
    select u.public_id,
           u.scope_id,
           u.name,
           u.description,
           u.create_time,
           u.update_time,
           u.version,
           i.primary_account_id,
           i.login_name,
           i.full_name,
           i.email
      from iam_user u
      left outer join iam_acct_info i
        on u.public_id = i.iam_user_id;

commit;
