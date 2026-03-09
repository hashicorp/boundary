// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/billing"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	billingservice "github.com/hashicorp/boundary/internal/daemon/controller/handlers/billing"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/billing"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MonthlyActiveUsers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")

	repoFn := func() (*billing.Repository, error) {
		return billing.TestRepo(t, conn), nil
	}
	billing.TestGenerateActiveUsers(t, conn)

	wrap := db.TestWrapper(t)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrap), nil
	}

	today := time.Now().UTC()
	// Some time calculations are impacted when using the current day vs. the
	// start of the month. For example, if...
	// today -> May 30th
	// today.AddDate(0, -3, 0).Month() -> March
	// February was expected here, but we get March. This seems to be a
	// rounding thing since February 30th is not a valid date. Instead, the
	// start of the month is used to ensure the correct months are calculated.
	monthStart := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)
	threeMonthsAgo := time.Date(monthStart.AddDate(0, -3, 0).Year(), monthStart.AddDate(0, -3, 0).Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01")
	oneMonthAgo := time.Date(monthStart.AddDate(0, -1, 0).Year(), monthStart.AddDate(0, -1, 0).Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01")
	badFormat := time.Date(today.Year(), today.Month(), 15, 0, 0, 0, 0, time.UTC).String()

	cases := []struct {
		name        string
		req         *pbs.MonthlyActiveUsersRequest
		res         *pbs.MonthlyActiveUsersResponse
		errContains string
	}{
		{
			name: "Valid no options, current and previous months",
			req:  &pbs.MonthlyActiveUsersRequest{},
			res: &pbs.MonthlyActiveUsersResponse{
				Items: []*pb.ActiveUsers{
					{
						Count:     0,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month(), today.Day(), today.Hour(), 0, 0, 0, time.UTC)),
					},
					{
						Count:     6,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month()-1, 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)),
					},
				},
			},
		},
		{
			name: "Valid start time",
			req:  &pbs.MonthlyActiveUsersRequest{StartTime: threeMonthsAgo},
			res: &pbs.MonthlyActiveUsersResponse{
				Items: []*pb.ActiveUsers{
					{
						Count:     0,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month(), today.Day(), today.Hour(), 0, 0, 0, time.UTC)),
					},
					{
						Count:     6,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month()-1, 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)),
					},
					{
						Count:     6,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month()-2, 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month()-1, 1, 0, 0, 0, 0, time.UTC)),
					},
					{
						Count:     6,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month()-3, 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month()-2, 1, 0, 0, 0, 0, time.UTC)),
					},
				},
			},
		},
		{
			name: "Valid start and end time",
			req:  &pbs.MonthlyActiveUsersRequest{StartTime: threeMonthsAgo, EndTime: oneMonthAgo},
			res: &pbs.MonthlyActiveUsersResponse{
				Items: []*pb.ActiveUsers{
					{
						Count:     6,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month()-2, 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month()-1, 1, 0, 0, 0, 0, time.UTC)),
					},
					{
						Count:     6,
						StartTime: timestamppb.New(time.Date(today.Year(), today.Month()-3, 1, 0, 0, 0, 0, time.UTC)),
						EndTime:   timestamppb.New(time.Date(today.Year(), today.Month()-2, 1, 0, 0, 0, 0, time.UTC)),
					},
				},
			},
		},
		{
			name:        "Invalid end time without start time",
			req:         &pbs.MonthlyActiveUsersRequest{EndTime: oneMonthAgo},
			errContains: "end time set without start time",
		},
		{
			name:        "Invalid end time before start time",
			req:         &pbs.MonthlyActiveUsersRequest{StartTime: oneMonthAgo, EndTime: threeMonthsAgo},
			errContains: "start time is not before end time",
		},
		{
			name:        "Invalid start time equals end time",
			req:         &pbs.MonthlyActiveUsersRequest{StartTime: threeMonthsAgo, EndTime: threeMonthsAgo},
			errContains: "start time is not before end time",
		},
		{
			name:        "Invalid start time format",
			req:         &pbs.MonthlyActiveUsersRequest{StartTime: badFormat},
			errContains: "start time is in an invalid format",
		},
		{
			name:        "Invalid end time format",
			req:         &pbs.MonthlyActiveUsersRequest{StartTime: threeMonthsAgo, EndTime: badFormat},
			errContains: "end time is in an invalid format",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := billingservice.NewService(ctx, repoFn)
			require.NoError(t, err, "Couldn't create new billing service.")

			got, gErr := b.MonthlyActiveUsers(auth.DisabledAuthTestContext(iamRepoFn, scope.Global.String(), auth.WithUserId(globals.AnyAuthenticatedUserId)), tc.req)
			if tc.errContains != "" {
				require.ErrorContains(t, gErr, tc.errContains)
				require.Nil(t, got)
				return
			} else {
				require.NoError(t, gErr)
			}
			assert.Empty(t,
				cmp.Diff(
					got,
					tc.res,
					protocmp.Transform(),
					protocmp.SortRepeatedFields(got),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
				))
		})
	}
}
