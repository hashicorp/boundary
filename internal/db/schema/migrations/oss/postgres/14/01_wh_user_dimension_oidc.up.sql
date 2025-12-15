-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table wh_user_dimension
    add column auth_method_external_id  text,
    add column auth_account_external_id text,
    add column auth_account_full_name   text,
    add column auth_account_email       text
  ;

  update wh_user_dimension
  set auth_method_type =
        case when auth_method_id like 'ampw_%' then 'password auth method'
             when auth_method_id like 'amoidc_%' then 'oidc auth method'
             else 'Unknown' end,
      auth_account_type =
        case when auth_account_id like 'acctpw_%' then 'password auth account'
             when auth_account_id like 'acctoidc_%' then 'oidc auth account'
             else 'Unknown' end,
      auth_method_external_id =
        case when auth_method_id like 'ampw_%' then 'Not Applicable'
             else 'Unknown' end,
      auth_account_external_id =
        case when auth_method_id like 'ampw_%' then 'Not Applicable'
             else 'Unknown' end,
      auth_account_full_name =
        case when auth_method_id like 'ampw_%' then 'Not Applicable'
             else 'Unknown' end,
      auth_account_email =
        case when auth_method_id like 'ampw_%' then 'Not Applicable'
             else 'Unknown' end;

  alter table wh_user_dimension
    alter column auth_method_external_id  type wh_dim_text,
    alter column auth_account_external_id type wh_dim_text,
    alter column auth_account_full_name   type wh_dim_text,
    alter column auth_account_email       type wh_dim_text
  ;

-- Replaced in 64/01_wh_user_dimension_ldap.up.sql
  drop view whx_user_dimension_source;
  create view whx_user_dimension_source as
       select -- id is the first column in the target view
              u.public_id                       as user_id,
              coalesce(u.name, 'None')          as user_name,
              coalesce(u.description, 'None')   as user_description,
              coalesce(aa.public_id, 'None')    as auth_account_id,
              case
                   when apa.public_id is not null then 'password auth account'
                   when aoa.public_id is not null then 'oidc auth account'
                   else 'None'
                   end                          as auth_account_type,
              case
                   when apa.public_id is not null then coalesce(apa.name, 'None')
                   when aoa.public_id is not null then coalesce(aoa.name, 'None')
                   else 'None'
                   end                          as auth_account_name,
              case
                   when apa.public_id is not null then coalesce(apa.description, 'None')
                   when aoa.public_id is not null then coalesce(aoa.description, 'None')
                   else 'None'
                   end                          as auth_account_description,
              case
                  when apa.public_id is not null then 'Not Applicable'
                  when aoa.public_id is null then 'None'
                  else aoa.subject
                  end                           as auth_account_external_id,
              case
                  when apa.public_id is not null then 'Not Applicable'
                  when  aoa.public_id is not null
                    and aoa.full_name is not null then aoa.full_name
                  else 'None'
                  end                           as auth_account_full_name,
              case
                  when apa.public_id is not null then 'Not Applicable'
                  when  aoa.public_id is not null
                    and aoa.email is not null then aoa.email
                  else 'None'
                  end                           as auth_account_email,
              coalesce(am.public_id, 'None')    as auth_method_id,
              case
                   when apa.public_id is not null then 'password auth method'
                   when aoa.public_id is not null then 'oidc auth method'
                   else 'None'
                   end                          as auth_method_type,
              case
                   when apm.public_id is not null then coalesce(apm.name, 'None')
                   when aom.public_id is not null then coalesce(aom.name, 'None')
                   else 'None'
                   end                          as auth_method_name,
              case
                   when apm.public_id is not null then coalesce(apm.description, 'None')
                   when aom.public_id is not null then coalesce(aom.description, 'None')
                   else 'None'
                   end                          as auth_method_description,
              case
                  when apa.public_id is not null then 'Not Applicable'
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
         join iam_scope as org on             u.scope_id        = org.public_id
  ;

  drop view whx_user_dimension_target;
  create view whx_user_dimension_target as
    select id,
           user_id,
           user_name,
           user_description,
           auth_account_id,
           auth_account_type,
           auth_account_name,
           auth_account_description,
           auth_account_external_id,
           auth_account_full_name,
           auth_account_email,
           auth_method_id,
           auth_method_type,
           auth_method_name,
           auth_method_description,
           auth_method_external_id,
           user_organization_id,
           user_organization_name,
           user_organization_description
      from wh_user_dimension
     where current_row_indicator = 'Current'
  ;

  drop function wh_upsert_user;
  create function wh_upsert_user(p_user_id wt_user_id, p_auth_token_id wt_public_id) returns wh_dim_id
  as $$
  declare
    src     whx_user_dimension_target%rowtype;
    target  whx_user_dimension_target%rowtype;
    new_row wh_user_dimension%rowtype;
    acct_id wt_public_id;
  begin
    select auth_account_id into strict acct_id
      from auth_token
     where public_id = p_auth_token_id;

    select * into target
      from whx_user_dimension_target as t
     where t.user_id               = p_user_id
       and t.auth_account_id       = acct_id;

    select target.id, t.* into src
      from whx_user_dimension_source as t
     where t.user_id               = p_user_id
       and t.auth_account_id       = acct_id;

    if src is distinct from target then

      -- expire the current row
      update wh_user_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where user_id               = p_user_id
         and auth_account_id       = acct_id
         and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_user_dimension (
             user_id,                  user_name,              user_description,
             auth_account_id,          auth_account_type,      auth_account_name,             auth_account_description,
             auth_account_external_id, auth_account_full_name, auth_account_email,
             auth_method_id,           auth_method_type,       auth_method_name,              auth_method_description,
             auth_method_external_id,
             user_organization_id,     user_organization_name, user_organization_description,
             current_row_indicator,    row_effective_time,     row_expiration_time
      )
      select user_id,                  user_name,              user_description,
             auth_account_id,          auth_account_type,      auth_account_name,             auth_account_description,
             auth_account_external_id, auth_account_full_name, auth_account_email,
             auth_method_id,           auth_method_type,       auth_method_name,              auth_method_description,
             auth_method_external_id,
             user_organization_id,     user_organization_name, user_organization_description,
             'Current',                current_timestamp,      'infinity'::timestamptz
        from whx_user_dimension_source
       where user_id               = p_user_id
         and auth_account_id       = acct_id
      returning * into new_row;

      return new_row.id;
    end if;
    return target.id;

  end;
  $$ language plpgsql;

commit;
