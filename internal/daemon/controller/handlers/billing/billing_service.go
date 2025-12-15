// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/billing"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/billing"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet()

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.MonthlyActiveUsers,
	)
)

func init() {
	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.Billing, IdActions, CollectionActions)
}

type Service struct {
	pbs.UnsafeBillingServiceServer

	repoFn common.BillingRepoFactory
}

var _ pbs.BillingServiceServer = (*Service)(nil)

// NewService returns a billing service which handles billing related requests to boundary.
func NewService(
	ctx context.Context,
	repoFn common.BillingRepoFactory,
) (Service, error) {
	const op = "billing.NewService"
	if repoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing billing repository")
	}
	return Service{
		repoFn: repoFn,
	}, nil
}

func (s Service) MonthlyActiveUsers(ctx context.Context, req *pbs.MonthlyActiveUsersRequest) (*pbs.MonthlyActiveUsersResponse, error) {
	const op = "billing.(Service).MonthlyActiveUsers"

	authResults := s.authResult(ctx, action.MonthlyActiveUsers, false)
	if authResults.Error != nil {
		return nil, errors.Wrap(ctx, authResults.Error, op)
	}

	// Get the billing information
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var startTime, endTime *time.Time
	if req.GetStartTime() != "" {
		st, err := time.Parse("2006-01", req.GetStartTime())
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "start time is in an invalid format")
		}
		startTime = &st
	}
	if req.GetEndTime() != "" {
		et, err := time.Parse("2006-01", req.GetEndTime())
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "end time is in an invalid format")
		}
		endTime = &et
	}
	if startTime != nil && endTime != nil && !endTime.After(*startTime) {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "start time is not before end time")
	}

	months, err := repo.MonthlyActiveUsers(
		ctx,
		billing.WithStartTime(startTime),
		billing.WithEndTime(endTime),
	)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, err.Error())
	}

	var activeUsers []*pb.ActiveUsers
	for _, month := range months {
		maud := &pb.ActiveUsers{
			StartTime: timestamppb.New(month.StartTime),
			EndTime:   timestamppb.New(month.EndTime),
			Count:     month.ActiveUsersCount,
		}
		activeUsers = append(activeUsers, maud)
	}

	return &pbs.MonthlyActiveUsersResponse{Items: activeUsers}, nil
}

func (s Service) authResult(ctx context.Context, a action.Type, isRecursive bool) auth.VerifyResults {
	opts := []auth.Option{
		auth.WithAction(a),
		auth.WithScopeId(scope.Global.String()),
		auth.WithRecursive(isRecursive),
	}
	return auth.Verify(ctx, resource.Billing, opts...)
}
