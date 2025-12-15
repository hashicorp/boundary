// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package policies

import (
	"context"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	internalglobals "github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pbs.PolicyServiceServer = (*Service)(nil)

	// idActions contains the set of actions that can be performed on individual
	// resources.
	idActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
	)
	// CollectionActions contains the set of actions that can be performed on
	// this collection.
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

// NewServiceFn returns a policy service which is not implemented in OSS
var NewServiceFn = func(ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	maxPageSize uint,
	controllerExt internalglobals.ControllerExtension,
) (pbs.PolicyServiceServer, error) {
	return &Service{}, nil
}

func init() {
	action.RegisterResource(resource.Policy, idActions, CollectionActions)
}

type Service struct {
	pbs.UnimplementedPolicyServiceServer
}

// GetPolicy implements the interface pbs.PolicyServiceServer.
func (s *Service) GetPolicy(ctx context.Context, req *pbs.GetPolicyRequest) (*pbs.GetPolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Policies are an Enterprise-only feature")
}

// ListPolicies implements the interface pbs.PolicyServiceServer.
func (s *Service) ListPolicies(ctx context.Context, req *pbs.ListPoliciesRequest) (*pbs.ListPoliciesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Policies are an Enterprise-only feature")
}

// CreatePolicy implements the interface pbs.PolicyServiceServer.
func (s *Service) CreatePolicy(ctx context.Context, req *pbs.CreatePolicyRequest) (*pbs.CreatePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Policies are an Enterprise-only feature")
}

// UpdatePolicy implements the interface pbs.PolicyServiceServer.
func (s *Service) UpdatePolicy(ctx context.Context, req *pbs.UpdatePolicyRequest) (*pbs.UpdatePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Policies are an Enterprise-only feature")
}

func (s *Service) DeletePolicy(ctx context.Context, req *pbs.DeletePolicyRequest) (*pbs.DeletePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Policies are an Enterprise-only feature")
}
