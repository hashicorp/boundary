-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  drop view whx_user_dimension_source;
  create view whx_user_dimension_source as
       select -- id is the first column in the target view
              u.public_id                       as user_id,
              coalesce(u.name, 'None')          as user_name,
              coalesce(u.description, 'None')   as user_description,
              coalesce(aa.public_id, 'None')    as auth_account_id,
              case
                   when apa.public_id is not null then 'password auth account'
                   when ala.public_id is not null then 'ldap auth account'
                   when aoa.public_id is not null then 'oidc auth account'
                   else 'None'
                   end                          as auth_account_type,
              case
                   when apa.public_id is not null then coalesce(apa.name, 'None')
                   when ala.public_id is not null then coalesce(ala.name, 'None')
                   when aoa.public_id is not null then coalesce(aoa.name, 'None')
                   else 'None'
                   end                          as auth_account_name,
              case
                   when apa.public_id is not null then coalesce(apa.description, 'None')
                   when ala.public_id is not null then coalesce(ala.description, 'None')
                   when aoa.public_id is not null then coalesce(aoa.description, 'None')
                   else 'None'
                   end                          as auth_account_description,
              case
                  when apa.public_id is not null then 'Not Applicable'
                  when ala.public_id is not null then ala.login_name
                  when aoa.public_id is not null then aoa.subject
                  else 'None'
                  end                           as auth_account_external_id,
              case
                  when apa.public_id is not null then 'Not Applicable'
                  when  ala.public_id is not null
                    and ala.full_name is not null then ala.full_name
                  when  aoa.public_id is not null
                    and aoa.full_name is not null then aoa.full_name
                  else 'None'
                  end                           as auth_account_full_name,
              case
                  when apa.public_id is not null then 'Not Applicable'
                  when  ala.public_id is not null
                    and ala.email is not null then ala.email
                  when  aoa.public_id is not null
                    and aoa.email is not null then aoa.email
                  else 'None'
                  end                           as auth_account_email,
              coalesce(am.public_id, 'None')    as auth_method_id,
              case
                   when apa.public_id is not null then 'password auth method'
                   when ala.public_id is not null then 'ldap auth method'
                   when aoa.public_id is not null then 'oidc auth method'
                   else 'None'
                   end                          as auth_method_type,
              case
                   when apm.public_id is not null then coalesce(apm.name, 'None')
                   when alm.public_id is not null then coalesce(alm.name, 'None')
                   when aom.public_id is not null then coalesce(aom.name, 'None')
                   else 'None'
                   end                          as auth_method_name,
              case
                   when apm.public_id is not null then coalesce(apm.description, 'None')
                   when alm.public_id is not null then coalesce(alm.description, 'None')
                   when aom.public_id is not null then coalesce(aom.description, 'None')
                   else 'None'
                   end                          as auth_method_description,
              case
                  when apa.public_id is not null then 'Not Applicable'
                  when alm.public_id is not null then 'Not Applicable'
                  when aom.public_id is null then 'None'
                  else aom.issuer
                  end                           as auth_method_external_id,
              org.public_id                     as user_organization_id,
              coalesce(org.name, 'None')        as user_organization_name,
              coalesce(org.description, 'None') as user_organization_description
         from iam_user as u
    left join auth_account as aa on           u.public_id       = aa.iam_user_id
    left join auth_method as am on            aa.auth_method_id = am.public_id
    left join auth_password_account as apa on aa.public_id      = apa.public_id
    left join auth_password_method as apm on  am.public_id      = apm.public_id
    left join auth_oidc_account as aoa on     aa.public_id      = aoa.public_id
    left join auth_oidc_method as aom on      am.public_id      = aom.public_id
    left join auth_ldap_account as ala on     aa.public_id      = ala.public_id
    left join auth_ldap_method as alm on      am.public_id      = alm.public_id
         join iam_scope as org on             u.scope_id        = org.public_id
  ;

commit;