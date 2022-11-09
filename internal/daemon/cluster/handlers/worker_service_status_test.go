package handlers_test

import (
	"context"
	"crypto/rand"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
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
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serverRepo, _ := server.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})
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
	require.NoError(t, err)

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms, new(atomic.Int64))
	require.NotNil(t, s)

	connection, _, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
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
				WorkerId:          worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
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
				},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:          worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
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
				assert.Equal(got, &pbs.StatusResponse{})
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
						pbs.SessionJobInfo{},
						pbs.Connection{},
						pbs.AuthorizedWorkerList{},
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

	serverRepo, _ := server.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})
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

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms, new(atomic.Int64))
	require.NotNil(t, s)

	connection, _, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
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
				WorkerId:          worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
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
						pbs.AuthorizedWorkerList{},
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

	serverRepo, _ := server.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})

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

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms, new(atomic.Int64))
	require.NotNil(t, s)

	connection, _, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
	require.NoError(t, err)
	deadConn, _, err := connRepo.AuthorizeConnection(ctx, sess2.PublicId, worker1.PublicId)
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
		WorkerId:          worker1.PublicId,
		AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
	}

	got, err := s.Status(ctx, req)
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
				pbs.AuthorizedWorkerList{},
			),
			cmpopts.IgnoreFields(pb.ServerWorkerStatus{}, "Tags"),
		),
	)

	gotConn, states, err := connRepo.LookupConnection(ctx, deadConn.PublicId)
	require.NoError(t, err)
	assert.Equal(t, session.ConnectionSystemError, session.ClosedReason(gotConn.ClosedReason))
	assert.Equal(t, 2, len(states))
	assert.Nil(t, states[0].EndTime)
	assert.Equal(t, session.StatusClosed, states[0].Status)
}

func TestStatusWorkerWithKeyId(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serverRepo, _ := server.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})
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

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms, new(atomic.Int64))
	require.NotNil(t, s)

	connection, _, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
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
				WorkerId:          worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
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
				WorkerId:          worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
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
						pbs.AuthorizedWorkerList{},
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

	serverRepo, _ := server.NewRepository(rw, rw, kmsCache)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})
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

	worker1 := server.TestKmsWorker(t, conn, wrapper)
	var w1KeyId, w2KeyId string
	_ = server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w1KeyId))
	_ = server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w2KeyId))

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kmsCache, new(atomic.Int64))
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
				ConnectedWorkerKeyIdentifiers: []string{},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId:          worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
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
				WorkerId:          worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{},
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
				ConnectedWorkerKeyIdentifiers: []string{w1KeyId, w2KeyId, "unknown"},
			},
			want: &pbs.StatusResponse{
				CalculatedUpstreams: []*pbs.UpstreamServer{
					{
						Type:    pbs.UpstreamServer_TYPE_CONTROLLER,
						Address: "127.0.0.1",
					},
				},
				WorkerId: worker1.PublicId,
				AuthorizedWorkers: &pbs.AuthorizedWorkerList{
					WorkerKeyIdentifiers: []string{w1KeyId, w2KeyId},
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
			sort.Strings(got.GetAuthorizedWorkers().GetWorkerKeyIdentifiers())
			sort.Strings(tc.want.GetAuthorizedWorkers().GetWorkerKeyIdentifiers())
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
						pbs.AuthorizedWorkerList{},
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

	serverRepo, _ := server.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})
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

	worker1 := server.TestKmsWorker(t, conn, wrapper)

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms, new(atomic.Int64))
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
			repoWorker, err := serverRepo.LookupWorkerByName(ctx, worker1.Name)
			require.NoError(err)
			assert.Equal(tc.wantState, repoWorker.OperationalState)
		})
	}
}
