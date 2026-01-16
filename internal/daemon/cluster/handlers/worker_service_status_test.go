// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStatus(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iamRepo)

	serverRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	serversRepoFn := func() (*server.Repository, error) {
		return serverRepo, nil
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opts...)
	}
	connRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	repo, err := sessionRepoFn()
	require.NoError(t, err)
	connRepo, err := connRepoFn()
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(
		ctx,
		t, conn, prj.GetPublicId(), "test",
		target.WithHostSources([]string{hs.GetPublicId()}),
		target.WithSessionConnectionLimit(-1),
	)

	worker1 := server.TestKmsWorker(t, conn, wrapper)

	canceledSess := session.TestDefaultSession(t, conn, wrapper, iamRepo)
	tofu := session.TestTofu(t)
	canceledSess, _, err = repo.ActivateSession(ctx, canceledSess.PublicId, canceledSess.Version, tofu)
	require.NoError(t, err)
	canceledConn, err := connRepo.AuthorizeConnection(ctx, canceledSess.PublicId, worker1.PublicId)
	require.NoError(t, err)

	canceledSess, err = repo.CancelSession(ctx, canceledSess.PublicId, canceledSess.Version)
	require.NoError(t, err)

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:          uId,
		HostId:          h.GetPublicId(),
		TargetId:        tar.GetPublicId(),
		HostSetId:       hs.GetPublicId(),
		AuthTokenId:     at.GetPublicId(),
		ProjectId:       prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu = session.TestTofu(t)
	sess, _, err = repo.ActivateSession(ctx, sess.PublicId, sess.Version, tofu)
	require.NoError(t, err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)

	connection, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
	require.NoError(t, err)

	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		req        *pbs.StatusRequest
		want       *pbs.StatusResponse
	}{
		{
			name:    "No Sessions",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
			},
		},
		{
			name:    "One unrecognized session",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
				Jobs: []*pbs.JobStatus{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: "unrecognized",
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
									Connections: []*pbs.Connection{
										{
											ConnectionId: canceledConn.PublicId,
											Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
										},
									},
								},
							},
						},
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: sess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
									Connections: []*pbs.Connection{
										{
											ConnectionId: connection.PublicId,
											Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
										},
									},
								},
							},
						},
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
							JobInfo: &pbs.Job_MonitorSessionInfo{
								MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
									SessionId: "unrecognized",
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
								},
							},
						},
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
							JobInfo: &pbs.Job_MonitorSessionInfo{
								MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
									SessionId: sess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
								},
							},
						},
					},
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
				JobsRequests: []*pbs.JobChangeRequest{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId:       "unrecognized",
									Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED,
									ProcessingError: pbs.SessionProcessingError_SESSION_PROCESSING_ERROR_UNRECOGNIZED,
								},
							},
						},
						RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
							JobInfo: &pbs.Job_MonitorSessionInfo{
								MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
									SessionId:       "unrecognized",
									Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_UNSPECIFIED,
									ProcessingError: pbs.SessionProcessingError_SESSION_PROCESSING_ERROR_UNRECOGNIZED,
								},
							},
						},
						RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
					},
				},
			},
		},
		{
			name:    "One Cancelled Session",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
				Jobs: []*pbs.JobStatus{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: canceledSess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
									Connections: []*pbs.Connection{
										{
											ConnectionId: canceledConn.PublicId,
											Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
										},
									},
								},
							},
						},
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: sess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
									Connections: []*pbs.Connection{
										{
											ConnectionId: connection.PublicId,
											Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
										},
									},
								},
							},
						},
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
							JobInfo: &pbs.Job_MonitorSessionInfo{
								MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
									SessionId: canceledSess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
								},
							},
						},
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
							JobInfo: &pbs.Job_MonitorSessionInfo{
								MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
									SessionId: sess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
								},
							},
						},
					},
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
				JobsRequests: []*pbs.JobChangeRequest{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: canceledSess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
								},
							},
						},
						RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
							JobInfo: &pbs.Job_MonitorSessionInfo{
								MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
									SessionId: canceledSess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
								},
							},
						},
						RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
					},
				},
			},
		},
		{
			name:    "Still Active",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
				Jobs: []*pbs.JobStatus{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: sess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
									Connections: []*pbs.Connection{
										{
											ConnectionId: connection.PublicId,
											Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
										},
									},
								},
							},
						},
					},
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_MONITOR_SESSION,
							JobInfo: &pbs.Job_MonitorSessionInfo{
								MonitorSessionInfo: &pbs.MonitorSessionJobInfo{
									SessionId: sess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
								},
							},
						},
					},
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
			},
		},
		{
			name:    "No Name or keyId",
			wantErr: true,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Address:  worker1.GetAddress(),
				},
			},
			wantErrMsg: status.Error(codes.InvalidArgument, "Name and keyId are not set in the request; one is required.").Error(),
		},
		{
			name:    "No Address",
			wantErr: true,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
				},
			},
			wantErrMsg: status.Error(codes.InvalidArgument, "Address is not set but is required.").Error(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := s.Status(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				assert.Equal(tc.wantErrMsg, err.Error())
				return
			}
			assert.Empty(
				cmp.Diff(
					tc.want,
					got,
					cmpopts.IgnoreUnexported(
						pbs.StatusResponse{},
						pb.ServerWorkerStatus{},
						pbs.UpstreamServer{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.Job_MonitorSessionInfo{},
						pbs.SessionJobInfo{},
						pbs.MonitorSessionJobInfo{},
						pbs.Connection{},
						pbs.AuthorizedDownstreamWorkerList{},
					),
					cmpopts.IgnoreFields(pb.ServerWorkerStatus{}, "Tags"),
				),
			)
		})
	}
}

func TestStatusSessionClosed(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serverRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	serversRepoFn := func() (*server.Repository, error) {
		return serverRepo, nil
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opts...)
	}
	connRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	repo, err := sessionRepoFn()
	require.NoError(t, err)
	connRepo, err := connRepoFn()
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(
		ctx,
		t, conn, prj.GetPublicId(), "test",
		target.WithHostSources([]string{hs.GetPublicId()}),
		target.WithSessionConnectionLimit(-1),
	)

	worker1 := server.TestKmsWorker(t, conn, wrapper)

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:          uId,
		HostId:          h.GetPublicId(),
		TargetId:        tar.GetPublicId(),
		HostSetId:       hs.GetPublicId(),
		AuthTokenId:     at.GetPublicId(),
		ProjectId:       prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu := session.TestTofu(t)
	sess, _, err = repo.ActivateSession(ctx, sess.PublicId, sess.Version, tofu)
	require.NoError(t, err)
	sess2 := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:          uId,
		HostId:          h.GetPublicId(),
		TargetId:        tar.GetPublicId(),
		HostSetId:       hs.GetPublicId(),
		AuthTokenId:     at.GetPublicId(),
		ProjectId:       prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu2 := session.TestTofu(t)
	sess2, _, err = repo.ActivateSession(ctx, sess2.PublicId, sess2.Version, tofu2)
	require.NoError(t, err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)

	connection, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
	require.NoError(t, err)

	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		setupFn    func(t *testing.T)
		req        *pbs.StatusRequest
		want       *pbs.StatusResponse
	}{
		{
			name:    "Connection Canceled",
			wantErr: false,
			setupFn: func(t *testing.T) {
				_, err := repo.CancelSession(ctx, sess2.PublicId, sess.Version)
				require.NoError(t, err)
			},
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
				Jobs: []*pbs.JobStatus{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: sess2.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
									Connections: []*pbs.Connection{
										{
											ConnectionId: connection.PublicId,
											Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
										},
									},
								},
							},
						},
					},
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				JobsRequests: []*pbs.JobChangeRequest{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: sess2.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
								},
							},
						},
						RequestType: pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			if tc.setupFn != nil {
				tc.setupFn(t)
			}
			got, err := s.Status(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Equal(tc.wantErrMsg, err.Error())
				return
			}
			fmt.Printf("want upstreams: %v, got upstreams: %v\n", tc.want.CalculatedUpstreams, got.CalculatedUpstreams)
			assert.Empty(
				cmp.Diff(
					tc.want,
					got,
					cmpopts.IgnoreUnexported(
						pbs.StatusResponse{},
						pb.ServerWorkerStatus{},
						pbs.UpstreamServer{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
						pbs.AuthorizedDownstreamWorkerList{},
					),
					cmpopts.IgnoreFields(pb.ServerWorkerStatus{}, "Tags"),
				),
			)
		})
	}
}

func TestStatusDeadConnection(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serverRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	worker1 := server.TestKmsWorker(t, conn, wrapper)

	serversRepoFn := func() (*server.Repository, error) {
		return serverRepo, nil
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opts...)
	}
	connRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms, session.WithWorkerStateDelay(0))
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	repo, err := sessionRepoFn()
	require.NoError(t, err)
	connRepo, err := connRepoFn()
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(
		ctx,
		t, conn, prj.GetPublicId(), "test",
		target.WithHostSources([]string{hs.GetPublicId()}),
		target.WithSessionConnectionLimit(-1),
	)

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:          uId,
		HostId:          h.GetPublicId(),
		TargetId:        tar.GetPublicId(),
		HostSetId:       hs.GetPublicId(),
		AuthTokenId:     at.GetPublicId(),
		ProjectId:       prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu := session.TestTofu(t)
	sess, _, err = repo.ActivateSession(ctx, sess.PublicId, sess.Version, tofu)
	require.NoError(t, err)
	sess2 := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:          uId,
		HostId:          h.GetPublicId(),
		TargetId:        tar.GetPublicId(),
		HostSetId:       hs.GetPublicId(),
		AuthTokenId:     at.GetPublicId(),
		ProjectId:       prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu2 := session.TestTofu(t)
	sess2, _, err = repo.ActivateSession(ctx, sess2.PublicId, sess2.Version, tofu2)
	require.NoError(t, err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)

	connection, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
	require.NoError(t, err)
	deadConn, err := connRepo.AuthorizeConnection(ctx, sess2.PublicId, worker1.PublicId)
	require.NoError(t, err)
	require.NotEqual(t, deadConn.PublicId, connection.PublicId)

	req := &pbs.StatusRequest{
		WorkerStatus: &pb.ServerWorkerStatus{
			PublicId: worker1.GetPublicId(),
			Name:     worker1.GetName(),
			Address:  worker1.GetAddress(),
		},
		Jobs: []*pbs.JobStatus{
			{
				Job: &pbs.Job{
					Type: pbs.JOBTYPE_JOBTYPE_SESSION,
					JobInfo: &pbs.Job_SessionInfo{
						SessionInfo: &pbs.SessionJobInfo{
							SessionId: sess.PublicId,
							Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
							Connections: []*pbs.Connection{
								{
									ConnectionId: connection.PublicId,
									Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
								},
							},
						},
					},
				},
			},
		},
	}
	want := &pbs.StatusResponse{
		CalculatedUpstreams: []*pbs.UpstreamServer{
			{
				Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
				Address: "127.0.0.1",
			},
		},
		WorkerId:                    worker1.PublicId,
		AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
	}

	got, err := s.Status(ctx, req)
	require.NoError(t, err)
	assert.Empty(t,
		cmp.Diff(
			want,
			got,
			cmpopts.IgnoreUnexported(
				pbs.StatusResponse{},
				pb.ServerWorkerStatus{},
				pbs.UpstreamServer{},
				pbs.JobChangeRequest{},
				pbs.Job{},
				pbs.Job_SessionInfo{},
				pbs.SessionJobInfo{},
				pbs.Connection{},
				pbs.AuthorizedDownstreamWorkerList{},
			),
			cmpopts.IgnoreFields(pb.ServerWorkerStatus{}, "Tags"),
		),
	)

	gotConn, err := connRepo.LookupConnection(ctx, deadConn.PublicId)
	require.NoError(t, err)
	assert.Equal(t, session.ConnectionSystemError, session.ClosedReason(gotConn.ClosedReason))
	assert.Equal(t, session.StatusClosed, session.ConnectionStatusFromString(gotConn.Status))
}

func TestStatusWorkerWithKeyId(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serverRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	serversRepoFn := func() (*server.Repository, error) {
		return serverRepo, nil
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opts...)
	}
	connRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	repo, err := sessionRepoFn()
	require.NoError(t, err)
	connRepo, err := connRepoFn()
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(
		ctx,
		t, conn, prj.GetPublicId(), "test",
		target.WithHostSources([]string{hs.GetPublicId()}),
		target.WithSessionConnectionLimit(-1),
	)

	worker1 := server.TestPkiWorker(t, conn, wrapper)

	rootStorage, err := server.NewRepositoryStorage(ctx, rw, rw, kms)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, rootStorage)
	require.NoError(t, err)

	// Create struct to pass in with workerId that will be passed along to storage
	state, err := server.AttachWorkerIdToState(ctx, worker1.PublicId)
	require.NoError(t, err)

	// This happens on the worker
	fileStorage, err := file.New(ctx)
	require.NoError(t, err)
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(t, err)
	// Create request using worker id
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)

	// The AuthorizeNode request will result in a WorkerAuth record being stored under the workerId
	nodeInfo, err := registration.AuthorizeNode(ctx, rootStorage, fetchReq, nodeenrollment.WithState(state))
	require.NoError(t, err)

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:          uId,
		HostId:          h.GetPublicId(),
		TargetId:        tar.GetPublicId(),
		HostSetId:       hs.GetPublicId(),
		AuthTokenId:     at.GetPublicId(),
		ProjectId:       prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu := session.TestTofu(t)
	sess, _, err = repo.ActivateSession(ctx, sess.PublicId, sess.Version, tofu)
	require.NoError(t, err)
	require.NoError(t, err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)

	connection, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
	require.NoError(t, err)

	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		req        *pbs.StatusRequest
		want       *pbs.StatusResponse
	}{
		{
			name:    "Identify workerID based on keyId in status",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					Address: "someaddress",
					KeyId:   nodeInfo.Id,
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
			},
		},
		{
			name:    "Active keyId Worker",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					KeyId:   nodeInfo.Id,
					Address: "someaddress",
				},
				Jobs: []*pbs.JobStatus{
					{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId: sess.PublicId,
									Status:    pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
									Connections: []*pbs.Connection{
										{
											ConnectionId: connection.PublicId,
											Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
										},
									},
								},
							},
						},
					},
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := s.Status(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Equal(got, &pbs.StatusResponse{})
				assert.Equal(tc.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Empty(
				cmp.Diff(
					tc.want,
					got,
					cmpopts.IgnoreUnexported(
						pbs.StatusResponse{},
						pb.ServerWorkerStatus{},
						pbs.UpstreamServer{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
						pbs.AuthorizedDownstreamWorkerList{},
					),
					cmpopts.IgnoreFields(pb.ServerWorkerStatus{}, "Tags"),
				),
			)
		})
	}
}

func TestStatusAuthorizedWorkers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(t, err)

	serverRepo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	serversRepoFn := func() (*server.Repository, error) {
		return serverRepo, nil
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kmsCache, opts...)
	}
	connRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kmsCache)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	worker1 := server.TestKmsWorker(t, conn, wrapper)
	var w1KeyId, w2KeyId string
	w1 := server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w1KeyId))
	w2 := server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w2KeyId))

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), kmsCache, new(atomic.Int64), fce)
	require.NotNil(t, s)

	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		req        *pbs.StatusRequest
		want       *pbs.StatusResponse
	}{
		{
			name:    "No downstreams",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
			},
		},
		{
			name:    "Unauthorized ConnectedWorkers",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:                    worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{},
			},
		},
		{
			name:    "Some authorized connected downstreams",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
				ConnectedUnmappedWorkerKeyIdentifiers: []string{w1KeyId, w2KeyId, "unknown"},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId: worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{
					UnmappedWorkerKeyIdentifiers: []string{w1KeyId, w2KeyId},
				},
			},
		},
		{
			name:    "Some authorized connected downstreams with worker public ids",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
				ConnectedUnmappedWorkerKeyIdentifiers: []string{w1KeyId, w2KeyId, "unknown"},
				ConnectedWorkerPublicIds:              []string{w1.GetPublicId(), "unknown"},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId: worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{
					UnmappedWorkerKeyIdentifiers: []string{w1KeyId, w2KeyId},
					WorkerPublicIds:              []string{w1.GetPublicId()},
				},
			},
		},
		{
			name:    "Some authorized connected downstreams with only worker public ids",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
				ConnectedUnmappedWorkerKeyIdentifiers: []string{w1KeyId, w2KeyId, "unknown"},
				ConnectedWorkerPublicIds:              []string{w1.GetPublicId(), w2.GetPublicId(), "unknown"},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId: worker1.PublicId,
				AuthorizedDownstreamWorkers: &pbs.AuthorizedDownstreamWorkerList{
					UnmappedWorkerKeyIdentifiers: []string{w1KeyId, w2KeyId},
					WorkerPublicIds:              []string{w1.GetPublicId(), w2.GetPublicId()},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := s.Status(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Equal(got, &pbs.StatusResponse{})
				assert.Equal(tc.wantErrMsg, err.Error())
				return
			}
			sort.Strings(got.GetAuthorizedDownstreamWorkers().GetWorkerPublicIds())
			sort.Strings(tc.want.GetAuthorizedDownstreamWorkers().GetWorkerPublicIds())
			sort.Strings(got.GetAuthorizedDownstreamWorkers().GetUnmappedWorkerKeyIdentifiers())
			sort.Strings(tc.want.GetAuthorizedDownstreamWorkers().GetUnmappedWorkerKeyIdentifiers())
			assert.Empty(
				cmp.Diff(
					tc.want,
					got,
					cmpopts.IgnoreUnexported(
						pbs.StatusResponse{},
						pb.ServerWorkerStatus{},
						pbs.UpstreamServer{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
						pbs.AuthorizedDownstreamWorkerList{},
					),
					cmpopts.IgnoreFields(pb.ServerWorkerStatus{}, "Tags"),
				),
			)
		})
	}
}

func TestWorkerOperationalStatus(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	serverRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	serversRepoFn := func() (*server.Repository, error) {
		return serverRepo, nil
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opt ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms)
	}
	connRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	worker1 := server.TestKmsWorker(t, conn, wrapper)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)

	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		req        *pbs.StatusRequest
		wantState  string
	}{
		{
			name:    "Active worker",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:         worker1.GetPublicId(),
					Name:             worker1.GetName(),
					Address:          worker1.GetAddress(),
					OperationalState: "active",
				},
			},
			wantState: "active",
		},
		{
			name:    "Worker in shutdown",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:         worker1.GetPublicId(),
					Name:             worker1.GetName(),
					Address:          worker1.GetAddress(),
					OperationalState: "shutdown",
				},
			},
			wantState: "shutdown",
		},
		{
			name:    "No operational state- default to unknown",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:       worker1.GetPublicId(),
					Name:           worker1.GetName(),
					Address:        worker1.GetAddress(),
					ReleaseVersion: "Boundary v0.11.0",
				},
			},
			wantState: "unknown",
		},
		{
			name:    "Old worker (empty release version) and  no operational state- default to active",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
			},
			wantState: "active",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := s.Status(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Equal(tc.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(got)
			repoWorker, err := server.TestLookupWorkerByName(ctx, t, worker1.Name, serverRepo)
			require.NoError(err)
			assert.Equal(tc.wantState, repoWorker.OperationalState)
		})
	}
}

func TestWorkerLocalStorageStateStatus(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	serverRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	serversRepoFn := func() (*server.Repository, error) {
		return serverRepo, nil
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opt ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms)
	}
	connRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	worker1 := server.TestKmsWorker(t, conn, wrapper)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)

	cases := []struct {
		name            string
		wantErr         bool
		wantErrContains string
		req             *pbs.StatusRequest
		wantState       string
	}{
		{
			name:    "Available local storage worker",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:          worker1.GetPublicId(),
					Name:              worker1.GetName(),
					Address:           worker1.GetAddress(),
					LocalStorageState: server.AvailableLocalStorageState.String(),
				},
			},
			wantState: server.AvailableLocalStorageState.String(),
		},
		{
			name:    "Worker in low local storage",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:          worker1.GetPublicId(),
					Name:              worker1.GetName(),
					Address:           worker1.GetAddress(),
					LocalStorageState: server.LowStorageLocalStorageState.String(),
				},
			},
			wantState: server.LowStorageLocalStorageState.String(),
		},
		{
			name:    "Worker in critically low local storage",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:          worker1.GetPublicId(),
					Name:              worker1.GetName(),
					Address:           worker1.GetAddress(),
					LocalStorageState: server.CriticallyLowStorageLocalStorageState.String(),
				},
			},
			wantState: server.CriticallyLowStorageLocalStorageState.String(),
		},
		{
			name:    "Worker in out of space local storage",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:          worker1.GetPublicId(),
					Name:              worker1.GetName(),
					Address:           worker1.GetAddress(),
					LocalStorageState: server.OutOfStorageLocalStorageState.String(),
				},
			},
			wantState: server.OutOfStorageLocalStorageState.String(),
		},
		{
			name:    "Worker in not configured local storage",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:          worker1.GetPublicId(),
					Name:              worker1.GetName(),
					Address:           worker1.GetAddress(),
					LocalStorageState: server.NotConfiguredLocalStorageState.String(),
				},
			},
			wantState: server.NotConfiguredLocalStorageState.String(),
		},
		{
			name:    "No local storage state - default to unknown",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:       worker1.GetPublicId(),
					Name:           worker1.GetName(),
					Address:        worker1.GetAddress(),
					ReleaseVersion: "Boundary v0.11.0",
				},
			},
			wantState: server.UnknownLocalStorageState.String(),
		},
		{
			name:    "Old worker (empty release version) and no local storage state - default to active",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId: worker1.GetPublicId(),
					Name:     worker1.GetName(),
					Address:  worker1.GetAddress(),
				},
			},
			wantState: server.UnknownLocalStorageState.String(),
		},
		{
			name:    "Worker with invalid local storage type",
			wantErr: true,
			req: &pbs.StatusRequest{
				WorkerStatus: &pb.ServerWorkerStatus{
					PublicId:          worker1.GetPublicId(),
					Name:              worker1.GetName(),
					Address:           worker1.GetAddress(),
					LocalStorageState: "invalid",
				},
			},
			wantErrContains: "foreign key constraint",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := s.Status(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			repoWorker, err := server.TestLookupWorkerByName(ctx, t, worker1.Name, serverRepo)
			require.NoError(err)
			assert.Equal(tc.wantState, repoWorker.LocalStorageState)
		})
	}
}
