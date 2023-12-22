// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtoken

const (
	estimateCountAuthTokens = `
select reltuples::bigint as estimate from pg_class where oid in ('auth_token'::regclass)
`
	listAuthTokensTemplate = `
  select at.public_id,
         at.auth_account_id,
         aa.scope_id,
         aa.auth_method_id,
         aa.iam_user_id,
         aa.iam_user_scope_id,
         at.create_time,
         at.update_time,
         at.approximate_last_access_time,
         at.expiration_time,
         at.status
    from auth_token at
    join auth_account aa on aa.public_id = at.auth_account_id
   where aa.scope_id in @scope_ids
order by at.create_time desc, at.public_id desc
   limit %d;
`
	listAuthTokensPageTemplate = `
  select at.public_id,
         at.auth_account_id,
         aa.scope_id,
         aa.auth_method_id,
         aa.iam_user_id,
         aa.iam_user_scope_id,
         at.create_time,
         at.update_time,
         at.approximate_last_access_time,
         at.expiration_time,
         at.status
    from auth_token at
    join auth_account aa on aa.public_id = at.auth_account_id
   where aa.scope_id in @scope_ids
     and (at.create_time, at.public_id) < (@last_item_create_time, @last_item_id)
order by at.create_time desc, at.public_id desc
   limit %d;
`
	refreshAuthTokensTemplate = `
  select at.public_id,
         at.auth_account_id,
         aa.scope_id,
         aa.auth_method_id,
         aa.iam_user_id,
         aa.iam_user_scope_id,
         at.create_time,
         at.update_time,
         at.approximate_last_access_time,
         at.expiration_time,
         at.status
    from auth_token at
    join auth_account aa on aa.public_id = at.auth_account_id
   where aa.scope_id in @scope_ids
     and at.update_time > @updated_after_time
order by at.update_time desc, at.public_id desc
   limit %d;
`
	refreshAuthTokensPageTemplate = `
  select at.public_id,
         at.auth_account_id,
         aa.scope_id,
         aa.auth_method_id,
         aa.iam_user_id,
         aa.iam_user_scope_id,
         at.create_time,
         at.update_time,
         at.approximate_last_access_time,
         at.expiration_time,
         at.status
    from auth_token at
    join auth_account aa on aa.public_id = at.auth_account_id
   where aa.scope_id in @scope_ids
     and at.update_time > @updated_after_time
     and (at.update_time, at.public_id) < (@last_item_update_time, @last_item_id)
order by at.update_time desc, at.public_id desc
   limit %d;
`
)
