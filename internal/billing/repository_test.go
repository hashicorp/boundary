// Copyright IBM Corp. 2020, 2025
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
			},
			want: &Repository{
				reader: rw,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "billing.NewRepository: nil db reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewRepository(context.Background(), tt.args.r)
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

	TestGenerateActiveUsers(t, conn)

	today := time.Now().UTC()
	// Some time calculations are impacted when using the current day vs. the
	// start of the month. For example, if...
	// today -> May 30th
	// today.AddDate(0, -3, 0).Month() -> March
	// February was expected here, but we get March. This seems to be a
	// rounding thing since February 30th is not a valid date. Instead, the
	// start of the month is used to ensure the correct months are calculated.
	monthStart := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)
	threeMonthsAgo := time.Date(monthStart.AddDate(0, -3, 0).Year(), monthStart.AddDate(0, -3, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
	oneMonthAgo := time.Date(monthStart.AddDate(0, -1, 0).Year(), monthStart.AddDate(0, -1, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
	midMonth := time.Date(today.Year(), today.Month(), 15, 0, 0, 0, 0, time.UTC)

	t.Run("valid-no-options", func(t *testing.T) {
		repo := TestRepo(t, conn)
		activeUsers, err := repo.MonthlyActiveUsers(ctx)
		assert.NoError(t, err)
		require.Len(t, activeUsers, 2)
		// check counts for the last two months
		require.Equal(t, uint32(0), activeUsers[0].ActiveUsersCount)
		require.Equal(t, uint32(6), activeUsers[1].ActiveUsersCount)
		// assert start and end times are correct
		// the current month (contains the hour)
		assert.Equal(t, time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC), activeUsers[0].StartTime)
		assert.Equal(t, time.Date(today.Year(), today.Month(), today.Day(), today.Hour(), 0, 0, 0, time.UTC), activeUsers[0].EndTime)
		// the previous month
		assert.Equal(t, time.Date(today.Year(), today.Month()-1, 1, 0, 0, 0, 0, time.UTC), activeUsers[1].StartTime)
		assert.Equal(t, time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC), activeUsers[1].EndTime)
	})

	t.Run("valid-with-start-time", func(t *testing.T) {
		repo := TestRepo(t, conn)
		activeUsers, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&threeMonthsAgo))
		assert.NoError(t, err)
		require.Len(t, activeUsers, 4)
		for i := 0; i < 4; i++ {
			// check counts for the last four months
			expectedStartTime := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)
			if i == 0 {
				assert.Equal(t, uint32(0), activeUsers[i].ActiveUsersCount)
				// the current month (contains the hour)
				assert.Equal(t, expectedStartTime, activeUsers[i].StartTime)
				assert.Equal(t, time.Date(today.Year(), today.Month(), today.Day(), today.Hour(), 0, 0, 0, time.UTC), activeUsers[i].EndTime)
			} else {
				// create a sliding window of dates to assert start and end times are correct
				// need to subtract month by month to prevent errors around month boundaries
				expectedStartTime = time.Date(expectedStartTime.AddDate(0, -i, 0).Year(), expectedStartTime.AddDate(0, -i, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
				expectedEndTime := time.Date(expectedStartTime.AddDate(0, 1, 0).Year(), expectedStartTime.AddDate(0, 1, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
				assert.Equal(t, uint32(6), activeUsers[i].ActiveUsersCount)
				assert.Equal(t, expectedStartTime, activeUsers[i].StartTime)
				assert.Equal(t, expectedEndTime, activeUsers[i].EndTime)
			}
		}
	})

	t.Run("valid-with-start-and-end-time", func(t *testing.T) {
		repo := TestRepo(t, conn)
		activeUsers, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&threeMonthsAgo), WithEndTime(&oneMonthAgo))
		assert.NoError(t, err)
		require.Len(t, activeUsers, 2)
		expectedStartTime := time.Date(monthStart.AddDate(0, -2, 0).Year(), monthStart.AddDate(0, -2, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
		expectedEndTime := time.Date(monthStart.AddDate(0, -1, 0).Year(), monthStart.AddDate(0, -1, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
		require.Equal(t, uint32(6), activeUsers[0].ActiveUsersCount)
		assert.Equal(t, expectedStartTime, activeUsers[0].StartTime)
		assert.Equal(t, expectedEndTime, activeUsers[0].EndTime)

		expectedStartTime = time.Date(monthStart.AddDate(0, -3, 0).Year(), monthStart.AddDate(0, -3, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
		expectedEndTime = time.Date(monthStart.AddDate(0, -2, 0).Year(), monthStart.AddDate(0, -2, 0).Month(), 1, 0, 0, 0, 0, time.UTC)
		require.Equal(t, uint32(6), activeUsers[1].ActiveUsersCount)
		assert.Equal(t, expectedStartTime, activeUsers[1].StartTime)
		assert.Equal(t, expectedEndTime, activeUsers[1].EndTime)
	})

	t.Run("invalid-end-time-without-start-time", func(t *testing.T) {
		repo := TestRepo(t, conn)
		_, err := repo.MonthlyActiveUsers(ctx, WithEndTime(&oneMonthAgo))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: end time set without start time: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-end-time-before-start-time", func(t *testing.T) {
		repo := TestRepo(t, conn)
		_, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&oneMonthAgo), WithEndTime(&threeMonthsAgo))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: start time is not before end time: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-start-time-equals-end-time", func(t *testing.T) {
		repo := TestRepo(t, conn)
		_, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&oneMonthAgo), WithEndTime(&oneMonthAgo))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: start time is not before end time: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-start-time-not-first-day-of-month", func(t *testing.T) {
		repo := TestRepo(t, conn)
		_, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&midMonth))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: start time must be the first day of the month at midnight UTC: parameter violation: error #100", err.Error())
	})

	t.Run("invalid-end-time-not-first-day-of-month", func(t *testing.T) {
		repo := TestRepo(t, conn)
		_, err := repo.MonthlyActiveUsers(ctx, WithStartTime(&oneMonthAgo), WithEndTime(&midMonth))
		assert.Error(t, err)
		assert.Equal(t, "billing.Repository.MonthlyActiveUsers: end time must be the first day of the month at midnight UTC: parameter violation: error #100", err.Error())
	})
}
