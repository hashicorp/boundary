// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
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

func TestRepository_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	type args struct {
		r db.Reader
		w db.Writer
	}

	tests := []struct {
		name       string
		args       args
		want       *Repository
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "valid",
			args: args{
				r: rw,
				w: rw,
			},
			want: &Repository{
				reader: rw,
				writer: rw,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
				w: rw,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "billing.NewRepository: nil db reader: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r: rw,
				w: nil,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "billing.NewRepository: nil db writer: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_MonthlyActiveUsers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	today := time.Now().UTC()
	threeMonthsAgo := time.Date(today.AddDate(0, -3, 0).Year(), today.AddDate(0, -3, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
	oneMonthAgo := time.Date(today.AddDate(0, -1, 0).Year(), today.AddDate(0, -1, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
	midMonth := time.Date(today.Year(), today.Month(), 15, 0, 0, 0, 0, time.UTC)

	db, err := conn.SqlDB(ctx)
	if err != nil {
		t.Errorf("error getting db connection %s", err)
	}
	_, err = db.Exec(insertQuery)
	if err != nil {
		t.Errorf("error %s", err)
	}

	t.Run("valid-no-options", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		activeUsers, err := repo.MonthlyActiveUsers(ctx)
		assert.NoError(t, err)
		require.Len(t, activeUsers, 2)
		// check counts for the last two months
		require.Equal(t, uint64(0), activeUsers[0].ActiveUsersCount)
		require.Equal(t, uint64(6), activeUsers[1].ActiveUsersCount)
		// assert start and end times are correct
		// the current month (contains the hour)
		assert.Equal(t, time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC), activeUsers[0].StartTime)
		assert.Equal(t, time.Date(today.Year(), today.Month(), today.Day(), today.Hour(), 0, 0, 0, time.UTC), activeUsers[0].EndTime)
		// the previous month
		assert.Equal(t, time.Date(today.Year(), today.Month()-1, 1, 0, 0, 0, 0, time.UTC), activeUsers[1].StartTime)
		assert.Equal(t, time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC), activeUsers[1].EndTime)
	})

	t.Run("valid-with-start-time", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		activeUsers, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&threeMonthsAgo))
		assert.NoError(t, err)
		require.Len(t, activeUsers, 4)
		for i := 0; i < 4; i++ {
			// check counts for the last four months
			if i == 0 {
				assert.Equal(t, uint64(0), activeUsers[i].ActiveUsersCount)
				// the current month (contains the hour)
				assert.Equal(t, time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC), activeUsers[i].StartTime)
				assert.Equal(t, time.Date(today.Year(), today.Month(), today.Day(), today.Hour(), 0, 0, 0, time.UTC), activeUsers[i].EndTime)
			} else {
				// create a sliding window of dates to assert start and end times are correct
				expectedStartTime := time.Date(today.AddDate(0, -i, 0).Year(), today.AddDate(0, -i, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
				expectedEndTime := time.Date(today.AddDate(0, -i+1, 0).Year(), today.AddDate(0, -i+1, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
				assert.Equal(t, uint64(6), activeUsers[i].ActiveUsersCount)
				assert.Equal(t, expectedStartTime, activeUsers[i].StartTime)
				assert.Equal(t, expectedEndTime, activeUsers[i].EndTime)
			}
		}
	})

	t.Run("valid-with-start-and-end-time", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		activeUsers, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&threeMonthsAgo), WithEndTime(&oneMonthAgo))
		assert.NoError(t, err)
		// since the end time is exclusive, we should only get one record of active users
		// for the month of three months ago
		require.Len(t, activeUsers, 1)
		require.Equal(t, uint64(6), activeUsers[0].ActiveUsersCount)
	})

	t.Run("invalid-end-time-without-start-time", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		_, err = repo.MonthlyActiveUsers(ctx, WithEndTime(&oneMonthAgo))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: end time set without start time: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-end-time-before-start-time", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		_, err = repo.MonthlyActiveUsers(ctx, WithStartTime(&oneMonthAgo), WithEndTime(&threeMonthsAgo))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: start time is not before end time: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-start-time-equals-end-time", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		_, err = repo.MonthlyActiveUsers(ctx, WithStartTime(&oneMonthAgo), WithEndTime(&oneMonthAgo))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: start time is not before end time: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-start-time-not-first-day-of-month", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		_, err = repo.MonthlyActiveUsers(ctx, WithStartTime(&midMonth))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: start time must be the first day of the month at midnight UTC: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-end-time-not-first-day-of-month", func(t *testing.T) {
		repo, err := NewRepository(ctx, rw, rw)
		assert.NoError(t, err)
		_, err = repo.MonthlyActiveUsers(ctx, WithStartTime(&oneMonthAgo), WithEndTime(&midMonth))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: end time must be the first day of the month at midnight UTC: parameter violation: error #100", err.Error())
	})
}
