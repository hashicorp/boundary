begin;

-- These additional columns track details around the different types of
-- auth accounts and auth methods.
alter table wh_user_dimension
    add column password_auth_account_login_name wh_dim_text default 'None',
    add column oidc_auth_account_subject        wh_dim_text default 'None',
    add column oidc_auth_account_issuer         wh_dim_text default 'None',
    add column oidc_auth_account_full_name      wh_dim_text default 'None',
    add column oidc_auth_account_email          wh_dim_text default 'None',
    add column oidc_auth_method_state           wh_dim_text default 'None',
    add column oidc_auth_method_issuer          wh_dim_text default 'None',
    add column oidc_auth_method_client_id       wh_dim_text default 'None'
;

-- Now that we have created the new columns with the 'None' values we want
-- all further inserts to have to be explicit about the value so remove
-- the defaults.
alter table wh_user_dimension
    alter column password_auth_account_login_name drop default,

    alter column oidc_auth_account_subject        drop default,
    alter column oidc_auth_account_issuer         drop default,
    alter column oidc_auth_account_full_name      drop default,
    alter column oidc_auth_account_email          drop default,

    alter column oidc_auth_method_state           drop default,
    alter column oidc_auth_method_issuer          drop default,
    alter column oidc_auth_method_client_id       drop default
;

-- Updating these views to be oidc aware and add additional
-- auth account and auth method details
drop view whx_user_dimension_source;
drop view whx_user_dimension_target;

create view whx_user_dimension_source as
   select -- id is the first column in the target view
          u.public_id                       as user_id,
          coalesce(u.name, 'None')          as user_name,
          coalesce(u.description, 'None')   as user_description,
          coalesce(aa.public_id, 'None')    as auth_account_id,
          case when aa.public_id is null then 'None'
               when aoa.public_id is not null then 'oidc auth account'
               else 'password auth account'
               end                          as auth_account_type,
          case when aoa.public_id is not null then coalesce(aoa.name, 'None')
               else coalesce(apa.name, 'None')
               end                          as auth_account_name,
          case when aoa.public_id is not null then coalesce(aoa.description, 'None')
               else coalesce(apa.description, 'None')
               end                          as auth_account_description,

          -- TODO: decide what to do when the representation of None colides with a valid value.
          coalesce(apa.login_name, 'None')  as password_auth_account_login_name,

          coalesce(aoa.subject, 'None')     as oidc_auth_account_subject,
          coalesce(aoa.issuer, 'None')      as oidc_auth_account_issuer,
          coalesce(aoa.full_name, 'None')   as oidc_auth_account_full_name,
          coalesce(aoa.email, 'None')       as oidc_auth_account_email,

          coalesce(am.public_id, 'None')    as auth_method_id,
          case when am.public_id is null then 'None'
               when aom.public_id is not null then 'oidc auth method'
               else 'password auth method'
               end                          as auth_method_type,
          case when am.public_id is null then 'None'
               when aom.public_id is not null then coalesce(aom.name, 'None')
               else coalesce(apm.name, 'None')
              end                           as auth_method_name,
          case when am.public_id is null then 'None'
               when aom.public_id is not null then coalesce(aom.description, 'None')
               else coalesce(apm.description, 'None')
              end                           as auth_method_description,
          coalesce(aom.state, 'None')       as oidc_auth_method_state,
          coalesce(aom.issuer, 'None')      as oidc_auth_method_issuer,
          coalesce(aom.client_id, 'None')   as oidc_auth_method_client_id,
          org.public_id                     as user_organization_id,
          coalesce(org.name, 'None')        as user_organization_name,
          coalesce(org.description, 'None') as user_organization_description
     from iam_user as u
left join auth_account as aa on           u.public_id = aa.iam_user_id
left join auth_method as am on            aa.auth_method_id = am.public_id
left join auth_password_account as apa on aa.public_id = apa.public_id
left join auth_password_method as apm on  am.public_id = apm.public_id
left join auth_oidc_account as aoa on     aa.public_id = aoa.public_id
left join auth_oidc_method as aom on      am.public_id = aom.public_id
     join iam_scope as org on             u.scope_id = org.public_id
;


create view whx_user_dimension_target as
select id,
       user_id,
       user_name,
       user_description,
       auth_account_id,
       auth_account_type,
       auth_account_name,
       auth_account_description,
       password_auth_account_login_name,
       oidc_auth_account_subject,
       oidc_auth_account_issuer,
       oidc_auth_account_full_name,
       oidc_auth_account_email,
       auth_method_id,
       auth_method_type,
       auth_method_name,
       auth_method_description,
       oidc_auth_method_state,
       oidc_auth_method_issuer,
       oidc_auth_method_client_id,
       user_organization_id,
       user_organization_name,
       user_organization_description
from wh_user_dimension
where current_row_indicator = 'Current'
;

commit;
