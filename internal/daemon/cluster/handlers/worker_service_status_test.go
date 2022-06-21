package handlers_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
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
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
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
		ScopeId:         prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu := session.TestTofu(t)
	sess, _, err = repo.ActivateSession(ctx, sess.PublicId, sess.Version, tofu)
	require.NoError(t, err)
	require.NoError(t, err)

	s := handlers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms)
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
				WorkerStatus: &pbs.ServerWorkerStatus{
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
				WorkerId: worker1.PublicId,
			},
		},
		{
			name:    "Still Active",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pbs.ServerWorkerStatus{
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
				WorkerId: worker1.PublicId,
			},
		},
		{
			name:    "No Name or keyId",
			wantErr: true,
			req: &pbs.StatusRequest{
				WorkerStatus: &pbs.ServerWorkerStatus{
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
				WorkerStatus: &pbs.ServerWorkerStatus{
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
						pbs.ServerWorkerStatus{},
						pbs.UpstreamServer{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
					),
					cmpopts.IgnoreFields(pbs.ServerWorkerStatus{}, "Tags"),
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
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
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
		ScopeId:         prj.GetPublicId(),
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
		ScopeId:         prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu2 := session.TestTofu(t)
	sess2, _, err = repo.ActivateSession(ctx, sess2.PublicId, sess2.Version, tofu2)
	require.NoError(t, err)

	s := handlers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms)
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
				WorkerStatus: &pbs.ServerWorkerStatus{
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
				WorkerId: worker1.PublicId,
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
						pbs.ServerWorkerStatus{},
						pbs.UpstreamServer{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
					),
					cmpopts.IgnoreFields(pbs.ServerWorkerStatus{}, "Tags"),
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
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
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
		ScopeId:         prj.GetPublicId(),
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
		ScopeId:         prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu2 := session.TestTofu(t)
	sess2, _, err = repo.ActivateSession(ctx, sess2.PublicId, sess2.Version, tofu2)
	require.NoError(t, err)

	s := handlers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms)
	require.NotNil(t, s)

	connection, _, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
	require.NoError(t, err)
	deadConn, _, err := connRepo.AuthorizeConnection(ctx, sess2.PublicId, worker1.PublicId)
	require.NoError(t, err)
	require.NotEqual(t, deadConn.PublicId, connection.PublicId)

	req := &pbs.StatusRequest{
		WorkerStatus: &pbs.ServerWorkerStatus{
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
		WorkerId: worker1.PublicId,
	}

	got, err := s.Status(ctx, req)
	assert.Empty(t,
		cmp.Diff(
			want,
			got,
			cmpopts.IgnoreUnexported(
				pbs.StatusResponse{},
				pbs.ServerWorkerStatus{},
				pbs.UpstreamServer{},
				pbs.JobChangeRequest{},
				pbs.Job{},
				pbs.Job_SessionInfo{},
				pbs.SessionJobInfo{},
				pbs.Connection{},
			),
			cmpopts.IgnoreFields(pbs.ServerWorkerStatus{}, "Tags"),
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
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
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
		ScopeId:         prj.GetPublicId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ConnectionLimit: 10,
	})
	tofu := session.TestTofu(t)
	sess, _, err = repo.ActivateSession(ctx, sess.PublicId, sess.Version, tofu)
	require.NoError(t, err)
	require.NoError(t, err)

	s := handlers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms)
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
				WorkerStatus: &pbs.ServerWorkerStatus{
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
				WorkerId: worker1.PublicId,
			},
		},
		{
			name:    "Active keyId Worker",
			wantErr: false,
			req: &pbs.StatusRequest{
				WorkerStatus: &pbs.ServerWorkerStatus{
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
				WorkerId: worker1.PublicId,
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
						pbs.ServerWorkerStatus{},
						pbs.UpstreamServer{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
					),
					cmpopts.IgnoreFields(pbs.ServerWorkerStatus{}, "Tags"),
				),
			)
		})
	}
}
