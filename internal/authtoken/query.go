// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtoken

const (
	estimateCountAuthTokens = `
select reltuples::bigint as estimate from pg_class where oid in ('auth_token'::regclass)
`
	listAuthTokensTemplate = `
with auth_tokens as (
     select public_id,
            auth_account_id,
            create_time,
            update_time,
            approximate_last_access_time,
            expiration_time,
            status
       from auth_token
   order by create_time desc, public_id asc
      limit %d
),
auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where %s
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
      from auth_tokens at
      join auth_accounts aa on aa.public_id = at.auth_account_id
)
  select *
    from final
order by create_time desc, public_id asc;
`
	listAuthTokensPageTemplate = `
with auth_tokens as (
     select public_id,
            auth_account_id,
            create_time,
            update_time,
            approximate_last_access_time,
            expiration_time,
            status
       from auth_token
      where (create_time, public_id) < (@last_item_create_time, @last_item_id)
   order by create_time desc, public_id asc
      limit %d
),
auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where %s
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
      from auth_tokens at
      join auth_accounts aa on aa.public_id = at.auth_account_id
)
  select *
    from final
order by create_time desc, public_id asc;
`
	refreshAuthTokensTemplate = `
with auth_tokens as (
     select public_id,
            auth_account_id,
            create_time,
            update_time,
            approximate_last_access_time,
            expiration_time,
            status
       from auth_token
      where update_time > @updated_after_time
   order by update_time desc, public_id asc
      limit %d
),
auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where %s
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
      from auth_tokens at
      join auth_accounts aa on aa.public_id = at.auth_account_id
)
  select *
    from final
order by update_time desc, public_id asc;
`
	refreshAuthTokensPageTemplate = `
with auth_tokens as (
     select public_id,
            auth_account_id,
            create_time,
            update_time,
            approximate_last_access_time,
            expiration_time,
            status
       from auth_token
      where update_time > @updated_after_time
        and (update_time, public_id) < (@last_item_update_time, @last_item_id)
   order by update_time desc, public_id asc
      limit %d
),
auth_accounts as (
    select public_id,
           auth_method_id,
           scope_id,
           iam_user_id,
           iam_user_scope_id
      from auth_account
     where %s
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
      from auth_tokens at
      join auth_accounts aa on aa.public_id = at.auth_account_id
)
  select *
    from final
order by update_time desc, public_id asc;
`
)
