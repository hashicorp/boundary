// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/require"
)

const insertQuery = `
with
  month_range (date_key, time_key, month) as (
    select wh_date_key(s), wh_time_key(s), s
      from generate_series(date_trunc('month', now()) - interval '1 year',
                           date_trunc('month', now()) - interval '1 month',
                           interval '1 month') as s
  ),
  users (user_id, u) as (
    select 'u_____user'||u, u
      from generate_series(1, 6, 1) as u
  ),
  user_key (key, user_id) as (
    insert into wh_user_dimension (
                user_id,                 user_name,                user_description,
                auth_account_id,         auth_account_type,        auth_account_name,             auth_account_description,
                auth_method_id,          auth_method_type,         auth_method_name,              auth_method_description,
                user_organization_id,    user_organization_name,   user_organization_description,
                current_row_indicator,
                row_effective_time,      row_expiration_time,
                auth_method_external_id, auth_account_external_id, auth_account_full_name,        auth_account_email)
         select users.user_id,           'None',                   'None',
                'a______acc1',           'None',                   'None',                        'None',
                'am______am1',           'None',                   'None',                        'None',
                'o______org1',           'None',                   'None',
                'current',
                now(),                   'infinity'::timestamptz,
                'None',                  'None',                   'None',                        'None'
           from users
      returning key, user_id
  ),
  tokens (date_key, time_key, user_id, token_id) as (
    select wh_date_key(s), wh_time_key(s), users.user_id, 't_____u'||users.u||'tok'||s as token_id
      from users,
           generate_series(date_trunc('month', now()) - interval '1 year',
                           date_trunc('month', now()) - interval '1 month',
                           interval '1 month') as s
  ),
  tokens_user_keys (date_key, time_key, user_id, token_id, user_key) as (
    select tokens.date_key, tokens.time_key, tokens.user_id, tokens.token_id, user_key.key
      from tokens
      join user_key
        on user_key.user_id = tokens.user_id
  ),
  auth_tokens (user_key, user_id, token_id, valid_range) as (
    select tokens_user_keys.user_key, tokens_user_keys.user_id, tokens_user_keys.token_id, tstzrange(month_range.month, month_range.month + interval '5 minutes', '[)')
      from tokens_user_keys
      join month_range
        on month_range.date_key = tokens_user_keys.date_key
       and month_range.time_key = tokens_user_keys.time_key
  )
  insert into wh_auth_token_accumulating_fact (
              auth_token_id,                                            user_key,
              auth_token_issued_date_key,                               auth_token_issued_time_key,                                auth_token_issued_time,
              auth_token_deleted_date_key,                              auth_token_deleted_time_key,                               auth_token_deleted_time,
              auth_token_approximate_last_access_date_key,              auth_token_approximate_last_access_time_key,               auth_token_approximate_last_access_time,
              auth_token_approximate_active_time_range,
              auth_token_valid_time_range,
              auth_token_count
  )
      select auth_tokens.token_id,                                      auth_tokens.user_key,
             wh_date_key(lower(auth_tokens.valid_range)),               wh_time_key(lower(auth_tokens.valid_range)),               lower(auth_tokens.valid_range),
             coalesce(wh_date_key(upper(auth_tokens.valid_range)), -1), coalesce(wh_time_key(upper(auth_tokens.valid_range)), -1), upper(auth_tokens.valid_range),
             wh_date_key(upper(auth_tokens.valid_range)),               wh_time_key(upper(auth_tokens.valid_range)),               upper(auth_tokens.valid_range),
             auth_tokens.valid_range,
             auth_tokens.valid_range,
             1
        from auth_tokens;
  `

// TestRepo creates a repo that can be used for various testing purposes.
func TestRepo(t testing.TB, conn *db.DB) *Repository {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)

	repo, err := NewRepository(ctx, rw)
	require.NoError(err)
	return repo
}

// TestGenerateActiveUsers is a test helper that populates the data warehouse
// with active users for the last twelve months.
func TestGenerateActiveUsers(t testing.TB, conn *db.DB) {
	t.Helper()
	db, err := conn.SqlDB(context.Background())
	require.NoError(t, err)
	_, err = db.Exec(insertQuery)
	require.NoError(t, err)
}
