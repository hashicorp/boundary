// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session_recordings

import (
	"context"
	"sync/atomic"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	intglobals "github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Download,
		action.Delete,
		action.ReApplyStoragePolicy,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.List,
	)
)

func init() {
	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.SessionRecording, IdActions, CollectionActions)
}

// NewServiceFn returns a storage bucket service which is not implemented in OSS
var NewServiceFn = func(ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	serverRepoFn common.ServersRepoFactory,
	workerRPCGracePeriod *atomic.Int64,
	kms *kms.Kms,
	maxPageSize uint,
	controllerExt intglobals.ControllerExtension,
) (pbs.SessionRecordingServiceServer, error) {
	return Service{}, nil
}

type Service struct {
	pbs.UnimplementedSessionRecordingServiceServer
}

var _ pbs.SessionRecordingServiceServer = (*Service)(nil)

// GetSessionRecording implements the interface pbs.SessionRecordingServiceServer.
func (s Service) GetSessionRecording(context.Context, *pbs.GetSessionRecordingRequest) (*pbs.GetSessionRecordingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "session recordings are an Enterprise-only feature")
}

// ListSessionRecordings implements the interface pbs.SessionRecordingServiceServer.
func (s Service) ListSessionRecordings(context.Context, *pbs.ListSessionRecordingsRequest) (*pbs.ListSessionRecordingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "session recordings are an Enterprise-only feature")
}

// Download implements the interface pbs.SessionRecordingServiceServer.
func (s Service) Download(*pbs.DownloadRequest, pbs.SessionRecordingService_DownloadServer) error {
	return status.Errorf(codes.Unimplemented, "session recordings are an Enterprise-only feature")
}

// ReApplyStoragePolicy implements the interface pbs.SessionRecordingServiceServer.
func (s Service) ReApplyStoragePolicy(context.Context, *pbs.ReApplyStoragePolicyRequest) (*pbs.ReApplyStoragePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "session recordings are an Enterprise-only feature")
}

// Delete implements the interface pbs.SessionRecordingServiceServer.
func (s Service) Delete(*pbs.DownloadRequest, *pbs.DeleteSessionRecordingRequest) error {
	return status.Errorf(codes.Unimplemented, "session recordings are an Enterprise-only feature")
}
