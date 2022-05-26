package workers_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatus(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serverRepo, _ := servers.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})
	serverRepo.UpsertWorkerStatus(ctx, servers.NewWorkerForStatus(scope.Global.String(),
		servers.WithAddress("127.0.0.1")))

	serversRepoFn := func() (*servers.Repository, error) {
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

	worker1 := servers.TestWorker(t, conn, wrapper)

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

	s := workers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms)
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
				Worker: &servers.Server{
					PrivateId:  worker1.PublicId,
					Address:    worker1.CanonicalAddress(),
					CreateTime: worker1.CreateTime,
					UpdateTime: worker1.UpdateTime,
				},
			},
			want: &pbs.StatusResponse{
				Controllers: []*servers.Server{
					{
						PrivateId: "test_controller1",
						Address:   "127.0.0.1",
					},
				},
			},
		},
		{
			name:    "Still Active",
			wantErr: false,
			req: &pbs.StatusRequest{
				Worker: &servers.Server{
					PrivateId:  worker1.PublicId,
					Address:    worker1.CanonicalAddress(),
					CreateTime: worker1.CreateTime,
					UpdateTime: worker1.UpdateTime,
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
				Controllers: []*servers.Server{
					{
						PrivateId: "test_controller1",
						Address:   "127.0.0.1",
					},
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
						servers.Server{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
					),
					cmpopts.IgnoreFields(servers.Server{}, "CreateTime", "UpdateTime"),
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

	serverRepo, _ := servers.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})
	serverRepo.UpsertWorkerStatus(ctx, servers.NewWorkerForStatus(scope.Global.String(),
		servers.WithAddress("127.0.0.1")))

	serversRepoFn := func() (*servers.Repository, error) {
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

	worker1 := servers.TestWorker(t, conn, wrapper)

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

	s := workers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms)
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
				Worker: &servers.Server{
					PrivateId:  worker1.PublicId,
					Address:    worker1.CanonicalAddress(),
					CreateTime: worker1.CreateTime,
					UpdateTime: worker1.UpdateTime,
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
				Controllers: []*servers.Server{
					{
						PrivateId: "test_controller1",
						Address:   "127.0.0.1",
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
						servers.Server{},
						pbs.JobChangeRequest{},
						pbs.Job{},
						pbs.Job_SessionInfo{},
						pbs.SessionJobInfo{},
						pbs.Connection{},
					),
					cmpopts.IgnoreFields(servers.Server{}, "CreateTime", "UpdateTime"),
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

	serverRepo, _ := servers.NewRepository(rw, rw, kms)
	serverRepo.UpsertController(ctx, &store.Controller{
		PrivateId: "test_controller1",
		Address:   "127.0.0.1",
	})

	worker1 := servers.TestWorker(t, conn, wrapper)

	serversRepoFn := func() (*servers.Repository, error) {
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

	s := workers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connRepoFn, new(sync.Map), kms)
	require.NotNil(t, s)

	connection, _, err := connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
	require.NoError(t, err)
	deadConn, _, err := connRepo.AuthorizeConnection(ctx, sess2.PublicId, worker1.PublicId)
	require.NoError(t, err)
	require.NotEqual(t, deadConn.PublicId, connection.PublicId)

	req := &pbs.StatusRequest{
		Worker: &servers.Server{
			PrivateId: worker1.GetWorkerReportedName(),
			Address:   worker1.GetWorkerReportedAddress(),
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
		Controllers: []*servers.Server{
			{
				PrivateId: "test_controller1",
				Address:   "127.0.0.1",
			},
		},
	}

	got, err := s.Status(ctx, req)
	assert.Empty(t,
		cmp.Diff(
			want,
			got,
			cmpopts.IgnoreUnexported(
				pbs.StatusResponse{},
				servers.Server{},
				pbs.JobChangeRequest{},
				pbs.Job{},
				pbs.Job_SessionInfo{},
				pbs.SessionJobInfo{},
				pbs.Connection{},
			),
			cmpopts.IgnoreFields(servers.Server{}, "CreateTime", "UpdateTime"),
		),
	)

	gotConn, states, err := connRepo.LookupConnection(ctx, deadConn.PublicId)
	require.NoError(t, err)
	assert.Equal(t, session.ConnectionSystemError, session.ClosedReason(gotConn.ClosedReason))
	assert.Equal(t, 2, len(states))
	assert.Nil(t, states[0].EndTime)
	assert.Equal(t, session.StatusClosed, states[0].Status)
}
