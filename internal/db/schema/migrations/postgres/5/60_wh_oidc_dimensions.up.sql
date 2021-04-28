begin;

  drop view whx_user_dimension_source;

  -- The whx_user_dimension_source view shows the current values in the
  -- operational tables of the user dimension.
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
              coalesce(am.public_id, 'None')    as auth_method_id,
              case when am.public_id is null then 'None'
                   when aom.public_id is not null then 'oidc auth method'
                   else 'password auth method'
                   end                          as auth_method_type,
              case when am.public_id is null then 'None'
                   when aom.public_id is not null then coalesce(aom.name, 'None')
                   else coalesce(apm.name, 'None')
                  end                          as auth_method_name,
              case when am.public_id is null then 'None'
                   when aom.public_id is not null then coalesce(aom.description, 'None')
                   else coalesce(apm.description, 'None')
                  end                          as auth_method_description,
              org.public_id                     as user_organization_id,
              coalesce(org.name, 'None')        as user_organization_name,
              coalesce(org.description, 'None') as user_organization_description
         from iam_user as u
    left join auth_account as aa on           u.public_id = aa.iam_user_id
    left join auth_method as am on            aa.auth_method_id = am.public_id
    left join auth_password_account as apa on aa.public_id = apa.public_id
    left join auth_password_method as apm on  am.public_id = apm.public_id
    left join auth_oidc_account as aoa on aa.public_id = aoa.public_id
    left join auth_oidc_method as aom on  am.public_id = aom.public_id
         join iam_scope as org on             u.scope_id = org.public_id
  ;

commit;
