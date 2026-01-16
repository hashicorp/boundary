// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloseOrphanedConnections(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	connRepo, err := NewConnectionRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)
	sessRepo, err := NewRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)

	serverRepo, _ := server.NewRepository(context.Background(), rw, rw, testKms)
	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(context.Background(), c)
	require.NoError(t, err)

	cases := []struct {
		name       string
		connRepo   *ConnectionRepository
		setup      func() (workerId string, conns []*Connection, expectedClosedConnections []string)
		wantErrMsg string
	}{
		{
			name: "missing connection repository",
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				return workerId, conns, expectedClosedConnections
			},
			wantErrMsg: "session.CloseOrphanedConnections: missing connection repository: parameter violation: error #100",
		},
		{
			name:     "empty worker id",
			connRepo: &ConnectionRepository{},
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				return workerId, conns, expectedClosedConnections
			},
			wantErrMsg: "session.CloseOrphanedConnections: missing worker id: parameter violation: error #100",
		},
		{
			name:     "nil sessions",
			connRepo: connRepo,
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				workerId = w.GetPublicId()
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name:     "empty connections",
			connRepo: connRepo,
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				workerId = w.GetPublicId()
				conns = make([]*Connection, 0)
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name:     "ignore unknown connection",
			connRepo: connRepo,
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				workerId = w.GetPublicId()
				conns = []*Connection{
					{
						PublicId: "c_dne",
					},
				}
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name:     "session already canceled",
			connRepo: connRepo,
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				authToken := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
				userId := authToken.GetIamUserId()
				hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
				hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
				host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
				static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
				tar := tcp.TestTarget(
					context.Background(),
					t, conn, prj.GetPublicId(), "test",
					target.WithHostSources([]string{hostSet.GetPublicId()}),
					target.WithSessionConnectionLimit(-1),
				)
				s1 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, TestTofu(t))
				require.NoError(t, err)
				require.NoError(t, err)
				_, err = connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.PublicId)
				require.NoError(t, err)
				_, err = sessRepo.CancelSession(context.Background(), s1.PublicId, s1.Version)
				require.NoError(t, err)
				workerId = w.GetPublicId()
				conns = []*Connection{}
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name:     "active session",
			connRepo: connRepo,
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				authToken := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
				userId := authToken.GetIamUserId()
				hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
				hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
				host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
				static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
				tar := tcp.TestTarget(
					context.Background(),
					t, conn, prj.GetPublicId(), "test",
					target.WithHostSources([]string{hostSet.GetPublicId()}),
					target.WithSessionConnectionLimit(-1),
				)
				s1 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, TestTofu(t))
				require.NoError(t, err)
				c1, err := connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.GetPublicId())
				require.NoError(t, err)
				workerId = w.GetPublicId()
				conns = []*Connection{
					{
						PublicId: c1.GetPublicId(),
					},
				}
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name:     "closed session",
			connRepo: connRepo,
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				authToken := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
				userId := authToken.GetIamUserId()
				hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
				hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
				host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
				static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
				tar := tcp.TestTarget(
					context.Background(),
					t, conn, prj.GetPublicId(), "test",
					target.WithHostSources([]string{hostSet.GetPublicId()}),
					target.WithSessionConnectionLimit(-1),
				)
				s1 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, TestTofu(t))
				require.NoError(t, err)
				c1, err := connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.PublicId)
				require.NoError(t, err)
				_, err = sessRepo.CancelSession(context.Background(), s1.PublicId, s1.Version)
				require.NoError(t, err)

				workerId = w.GetPublicId()
				conns = []*Connection{
					{
						PublicId: c1.GetPublicId(),
					},
				}
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name:     "multiple closed sessions",
			connRepo: connRepo,
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				authToken := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
				userId := authToken.GetIamUserId()
				hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
				hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
				host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
				static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
				tar := tcp.TestTarget(
					context.Background(),
					t, conn, prj.GetPublicId(), "test",
					target.WithHostSources([]string{hostSet.GetPublicId()}),
					target.WithSessionConnectionLimit(-1),
				)
				s1 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, TestTofu(t))
				require.NoError(t, err)
				c1, err := connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.PublicId)
				require.NoError(t, err)
				_, err = sessRepo.CancelSession(context.Background(), s1.PublicId, s1.Version)
				require.NoError(t, err)

				s2 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s2, _, err = sessRepo.ActivateSession(context.Background(), s2.PublicId, s2.Version, TestTofu(t))
				require.NoError(t, err)
				c2, err := connRepo.AuthorizeConnection(context.Background(), s2.PublicId, w.PublicId)
				require.NoError(t, err)
				_, err = sessRepo.CancelSession(context.Background(), s2.PublicId, s2.Version)
				require.NoError(t, err)

				workerId = w.GetPublicId()
				conns = []*Connection{
					{
						PublicId: c1.GetPublicId(),
					},
					{
						PublicId: c2.GetPublicId(),
					},
				}
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name: "close orphaned connections",
			connRepo: func() *ConnectionRepository {
				connRepo, err := NewConnectionRepository(context.Background(), rw, rw, testKms, WithWorkerStateDelay(0))
				require.NoError(t, err)
				return connRepo
			}(),
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				authToken := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
				userId := authToken.GetIamUserId()
				hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
				hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
				host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
				static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
				tar := tcp.TestTarget(
					context.Background(),
					t, conn, prj.GetPublicId(), "test",
					target.WithHostSources([]string{hostSet.GetPublicId()}),
					target.WithSessionConnectionLimit(-1),
				)
				s1 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, TestTofu(t))
				require.NoError(t, err)
				c1, err := connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.PublicId)
				require.NoError(t, err)
				s2 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s2, _, err = sessRepo.ActivateSession(context.Background(), s2.PublicId, s2.Version, TestTofu(t))
				require.NoError(t, err)
				c2, err := connRepo.AuthorizeConnection(context.Background(), s2.PublicId, w.PublicId)
				require.NoError(t, err)
				require.NotEqual(t, c1.PublicId, c2.PublicId)
				workerId = w.GetPublicId()
				conns = []*Connection{
					{
						PublicId: c2.GetPublicId(),
					},
				}
				expectedClosedConnections = []string{c1.PublicId}
				return workerId, conns, expectedClosedConnections
			},
		},
		{
			name: "multiple sessions and orphaned connections",
			connRepo: func() *ConnectionRepository {
				connRepo, err := NewConnectionRepository(context.Background(), rw, rw, testKms, WithWorkerStateDelay(0))
				require.NoError(t, err)
				return connRepo
			}(),
			setup: func() (workerId string, conns []*Connection, expectedClosedConnections []string) {
				w := server.TestKmsWorker(t, conn, wrapper)
				org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				authToken := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
				userId := authToken.GetIamUserId()
				hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
				hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
				host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
				static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
				tar := tcp.TestTarget(
					context.Background(),
					t, conn, prj.GetPublicId(), "test",
					target.WithHostSources([]string{hostSet.GetPublicId()}),
					target.WithSessionConnectionLimit(-1),
				)
				s1 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, TestTofu(t))
				require.NoError(t, err)
				c1, err := connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.PublicId)
				require.NoError(t, err)
				_, err = sessRepo.CancelSession(context.Background(), s1.PublicId, s1.Version)
				require.NoError(t, err)

				s2 := TestSession(t, conn, wrapper, ComposedOf{
					UserId:          userId,
					HostId:          host.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hostSet.GetPublicId(),
					AuthTokenId:     authToken.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				s2, _, err = sessRepo.ActivateSession(context.Background(), s2.PublicId, s2.Version, TestTofu(t))
				require.NoError(t, err)
				c2, err := connRepo.AuthorizeConnection(context.Background(), s2.PublicId, w.PublicId)
				require.NoError(t, err)
				c3, err := connRepo.AuthorizeConnection(context.Background(), s2.PublicId, w.PublicId)
				require.NoError(t, err)
				_, err = sessRepo.CancelSession(context.Background(), s2.PublicId, s2.Version)
				require.NoError(t, err)

				workerId = w.GetPublicId()
				conns = []*Connection{
					{
						PublicId: c1.GetPublicId(),
					},
					{
						PublicId: c2.GetPublicId(),
					},
				}
				expectedClosedConnections = []string{c3.PublicId}
				return workerId, conns, expectedClosedConnections
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NotNil(tc.setup)
			workerId, stats, expectedClosedConnections := tc.setup()
			actualClosedConnections, err := CloseOrphanedConnections(context.Background(), tc.connRepo, workerId, stats)
			if tc.wantErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.wantErrMsg)
				assert.Empty(actualClosedConnections)
				return
			}
			require.NoError(err)
			assert.Equal(expectedClosedConnections, actualClosedConnections)
			for _, connectionId := range expectedClosedConnections {
				conn, err := connRepo.LookupConnection(context.Background(), connectionId)
				require.NoError(err)
				assert.Equal(ConnectionSystemError, ClosedReason(conn.ClosedReason))
				assert.Equal(StatusClosed, ConnectionStatusFromString(conn.Status))
			}
		})
	}
}

func TestUpdateConnectionBytesUpDown(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	connRepo, err := NewConnectionRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)
	sessRepo, err := NewRepository(context.Background(), rw, rw, testKms)
	require.NoError(t, err)

	serverRepo, _ := server.NewRepository(context.Background(), rw, rw, testKms)
	c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
	_, err = serverRepo.UpsertController(context.Background(), c)
	require.NoError(t, err)

	t.Run("nil connection repo", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		err := UpdateConnectionBytesUpDown(context.Background(), nil, nil)
		require.Error(err)
		assert.ErrorContains(err, "missing connection repository")
	})

	t.Run("bytes up and bytes down", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := server.TestKmsWorker(t, conn, wrapper)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		authToken := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
		userId := authToken.GetIamUserId()
		hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
		hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
		host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
		tar := tcp.TestTarget(
			context.Background(),
			t, conn, prj.GetPublicId(), "test",
			target.WithHostSources([]string{hostSet.GetPublicId()}),
			target.WithSessionConnectionLimit(-1),
		)
		s1 := TestSession(t, conn, wrapper, ComposedOf{
			UserId:          userId,
			HostId:          host.GetPublicId(),
			TargetId:        tar.GetPublicId(),
			HostSetId:       hostSet.GetPublicId(),
			AuthTokenId:     authToken.GetPublicId(),
			ProjectId:       prj.GetPublicId(),
			Endpoint:        "tcp://127.0.0.1:22",
			ConnectionLimit: 10,
		})
		s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, TestTofu(t))
		require.NoError(err)
		c1, err := connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.GetPublicId())
		require.NoError(err)

		// write to active session
		var expectedBytesUp int64 = 1024
		var expectedBytesDown int64 = 2048
		conns := []*Connection{
			{
				PublicId:  c1.GetPublicId(),
				BytesUp:   expectedBytesUp,
				BytesDown: expectedBytesDown,
			},
		}
		err = UpdateConnectionBytesUpDown(context.Background(), connRepo, conns)
		require.NoError(err)
		conn, err := connRepo.LookupConnection(context.Background(), c1.PublicId)
		require.NoError(err)
		assert.Equal(StatusAuthorized, ConnectionStatusFromString(conn.Status))
		assert.Equal(expectedBytesUp, conn.BytesUp)
		assert.Equal(expectedBytesDown, conn.BytesDown)

		// write to canceled session
		_, err = sessRepo.CancelSession(context.Background(), s1.PublicId, s1.Version)
		require.NoError(err)
		expectedBytesUp = 4096
		expectedBytesDown = 8192
		conns = []*Connection{
			{
				PublicId:  c1.GetPublicId(),
				BytesUp:   expectedBytesUp,
				BytesDown: expectedBytesDown,
			},
		}
		err = UpdateConnectionBytesUpDown(context.Background(), connRepo, conns)
		require.NoError(err)
		conn, err = connRepo.LookupConnection(context.Background(), c1.PublicId)
		require.NoError(err)
		assert.Equal(expectedBytesUp, conn.BytesUp)
		assert.Equal(expectedBytesDown, conn.BytesDown)
	})
}
