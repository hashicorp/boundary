// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtoken

const (
	estimateCountAuthTokens = `
select reltuples::bigint as estimate from pg_class where oid in ('auth_token'::regclass)
`
	listAuthTokensTemplate = `
with auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where scope_id in %s
),
final as (
    select at.public_id,
           at.auth_account_id,
           aa.auth_method_id,
           aa.scope_id,
           aa.iam_user_id,
           aa.iam_user_scope_id,
           at.create_time,
           at.update_time,
           at.approximate_last_access_time,
           at.expiration_time,
           at.status 
      from auth_token at
      join auth_accounts aa on aa.public_id = at.auth_account_id
  order by at.create_time desc, at.public_id asc
     limit %d
)
  select *
    from final
order by create_time desc, public_id asc;
`
	listAuthTokensPageTemplate = `
with auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where scope_id in %s
),
final as (
    select at.public_id,
           at.auth_account_id,
           aa.auth_method_id,
           aa.scope_id,
           aa.iam_user_id,
           aa.iam_user_scope_id,
           at.create_time,
           at.update_time,
           at.approximate_last_access_time,
           at.expiration_time,
           at.status 
      from auth_token at
      join auth_accounts aa on aa.public_id = at.auth_account_id
     where (at.create_time, at.public_id) < (@last_item_create_time, @last_item_id)
  order by at.create_time desc, at.public_id asc
     limit %d
)
  select *
    from final
order by create_time desc, public_id asc;
`
	refreshAuthTokensTemplate = `
with auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where scope_id in %s
),
final as (
    select at.public_id,
           at.auth_account_id,
           aa.auth_method_id,
           aa.scope_id,
           aa.iam_user_id,
           aa.iam_user_scope_id,
           at.create_time,
           at.update_time,
           at.approximate_last_access_time,
           at.expiration_time,
           at.status 
      from auth_token at
      join auth_accounts aa on aa.public_id = at.auth_account_id
     where at.update_time > @updated_after_time
  order by at.update_time desc, at.public_id asc
     limit %d
)
  select *
    from final
order by update_time desc, public_id asc;
`
	refreshAuthTokensPageTemplate = `
with auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where scope_id in %s
),
final as (
    select at.public_id,
           at.auth_account_id,
           aa.auth_method_id,
           aa.scope_id,
           aa.iam_user_id,
           aa.iam_user_scope_id,
           at.create_time,
           at.update_time,
           at.approximate_last_access_time,
           at.expiration_time,
           at.status 
      from auth_token at
      join auth_accounts aa on aa.public_id = at.auth_account_id
     where at.update_time > @updated_after_time
       and (at.update_time, at.public_id) < (@last_item_update_time, @last_item_id)
  order by at.update_time desc, at.public_id asc
     limit %d
)
  select *
    from final
order by update_time desc, public_id asc;
`
)
