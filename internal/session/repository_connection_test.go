// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_ListConnection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms, WithLimit(testLimit))
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms, WithLimit(testLimit))
	require.NoError(t, err)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)

	type args struct {
		searchForSessionId string
		opt                []Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "no-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				searchForSessionId: session.PublicId,
				opt:                []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				searchForSessionId: session.PublicId,
			},
			wantCnt: repo.defaultLimit,
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				searchForSessionId: session.PublicId,
				opt:                []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "bad-session-id",
			createCnt: repo.defaultLimit + 1,
			args: args{
				searchForSessionId: "s_thisIsNotValid",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { i := AllocConnection(); return &i }(), "1=1")
			testConnections := []*Connection{}
			for i := 0; i < tt.createCnt; i++ {
				c := TestConnection(t, conn,
					session.PublicId,
					"127.0.0.1",
					22,
					"127.0.0.1",
					2222,
					"127.0.0.1",
				)
				testConnections = append(testConnections, c)
			}
			assert.Equal(tt.createCnt, len(testConnections))
			got, err := connRepo.ListConnectionsBySessionId(context.Background(), tt.args.searchForSessionId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
	t.Run("withOrder", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db.TestDeleteWhere(t, conn, func() any { i := AllocConnection(); return &i }(), "1=1")
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestConnection(t, conn,
				session.PublicId,
				"127.0.0.1",
				22,
				"127.0.0.1",
				2222,
				"127.0.0.1",
			)
		}
		got, err := connRepo.ListConnectionsBySessionId(context.Background(), session.PublicId, WithOrderByCreateTime(db.AscendingOrderBy))
		require.NoError(err)
		assert.Equal(wantCnt, len(got))

		for i := 0; i < len(got)-1; i++ {
			first := got[i].CreateTime.Timestamp.AsTime()
			second := got[i+1].CreateTime.Timestamp.AsTime()
			assert.True(first.Before(second))
		}
	})
}

func TestRepository_ConnectConnection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	setupFn := func() ConnectWith {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		tofu := TestTofu(t)
		_, _, err := repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
		require.NoError(t, err)
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
		return ConnectWith{
			ConnectionId:       c.PublicId,
			ClientTcpAddress:   "127.0.0.1",
			ClientTcpPort:      22,
			EndpointTcpAddress: "127.0.0.1",
			EndpointTcpPort:    2222,
			UserClientIp:       "127.0.0.1",
		}
	}
	tests := []struct {
		name        string
		connectWith ConnectWith
		wantErr     bool
		wantIsError errors.Code
	}{
		{
			name:        "valid",
			connectWith: setupFn(),
		},
		{
			name: "empty-SessionId",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.ConnectionId = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-ClientTcpAddress",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.ClientTcpAddress = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-ClientTcpPort",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.ClientTcpPort = 0
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-EndpointTcpAddress",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.EndpointTcpAddress = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-EndpointTcpPort",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.EndpointTcpPort = 0
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-UserClientIp",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.UserClientIp = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			c, err := connRepo.ConnectConnection(context.Background(), tt.connectWith)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(c)
			assert.Equal(StatusConnected, ConnectionStatusFromString(c.Status))
			gotConn, err := connRepo.LookupConnection(context.Background(), c.PublicId)
			require.NoError(err)
			assert.Equal(tt.connectWith.ClientTcpAddress, gotConn.ClientTcpAddress)
			assert.Equal(tt.connectWith.ClientTcpPort, gotConn.ClientTcpPort)
			assert.Equal(tt.connectWith.ClientTcpAddress, gotConn.ClientTcpAddress)
			assert.Equal(tt.connectWith.EndpointTcpAddress, gotConn.EndpointTcpAddress)
			assert.Equal(tt.connectWith.EndpointTcpPort, gotConn.EndpointTcpPort)
			assert.Equal(tt.connectWith.UserClientIp, gotConn.UserClientIp)
		})
	}
}

func TestRepository_DeleteConnection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)

	type args struct {
		connection *Connection
		opt        []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			args: args{
				connection: TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1"),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				connection: func() *Connection {
					c := AllocConnection()
					return &c
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "session.(ConnectionRepository).DeleteConnection: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				connection: func() *Connection {
					c := AllocConnection()
					id, err := newConnectionId(ctx)
					require.NoError(t, err)
					c.PublicId = id
					return &c
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "db.LookupById: record not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := connRepo.DeleteConnection(context.Background(), tt.args.connection.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.connection.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found, err := connRepo.LookupConnection(context.Background(), tt.args.connection.PublicId)
			assert.NoError(err)
			assert.Nil(found)

			err = db.TestVerifyOplog(t, rw, tt.args.connection.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
		})
	}
}

func TestRepository_orphanedConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require, assert := require.New(t), assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms, WithWorkerStateDelay(0))
	require.NoError(err)
	numConns := 12

	// Create two "workers". One will remain untouched while the other "goes
	// away and comes back" (worker 2).
	worker1 := server.TestKmsWorker(t, conn, wrapper)
	worker2 := server.TestKmsWorker(t, conn, wrapper)

	// Create a few sessions on each, activate, and authorize a connection
	var connIds []string
	var worker1ConnIds []string
	var worker2ConnIds []string
	for i := 0; i < numConns; i++ {
		serverId := worker1.PublicId
		if i%2 == 0 {
			serverId = worker2.PublicId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte("foo"))
		require.NoError(err)
		c, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Equal(StatusAuthorized, ConnectionStatusFromString(c.Status))
		connIds = append(connIds, c.GetPublicId())
		if i%2 == 0 {
			worker2ConnIds = append(worker2ConnIds, c.GetPublicId())
		} else {
			worker1ConnIds = append(worker1ConnIds, c.GetPublicId())
		}
	}

	// Mark half of the connections connected and leave the others authorized.
	// This is just to ensure we have a spread when we test it out.
	for i, connId := range connIds {
		if i%2 == 0 {
			cc, err := connRepo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
				UserClientIp:       "127.0.0.1",
			})
			require.NoError(err)
			require.Equal(StatusConnected, ConnectionStatusFromString(cc.Status))
		}
	}

	// Now, advertise only some of the connection IDs for worker 2. After,
	// all connection IDs for worker 1 should be showing as non-closed, and
	// the ones for worker 2 not advertised should be closed.
	shouldStayOpen := worker2ConnIds[0:2]
	found, err := connRepo.closeOrphanedConnections(ctx, worker2.GetPublicId(), shouldStayOpen)
	require.NoError(err)
	fmt.Printf("shouldstate: %v\nfound: %v\n", shouldStayOpen, found)
	require.Equal(4, len(found))

	// For the ones we didn't specify, we expect those to now be closed. We
	// expect all others to be open.

	shouldBeFound := worker2ConnIds[2:]
	assert.ElementsMatch(found, shouldBeFound)

	// Now, advertise none of the connection IDs for worker 2. This is mainly to
	// test that handling the case where we do not include IDs works properly as
	// it changes the where clause.
	found, err = connRepo.closeOrphanedConnections(ctx, worker1.GetPublicId(), nil)
	require.NoError(err)
	assert.Equal(6, len(found))
	assert.ElementsMatch(found, worker1ConnIds)
}

func TestRepository_CloseConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	setupFn := func(cnt int) []CloseWith {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		tofu := TestTofu(t)
		s, _, err := repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
		require.NoError(t, err)
		cw := make([]CloseWith, 0, cnt)
		for i := 0; i < cnt; i++ {
			c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
			require.NoError(t, err)
			cw = append(cw, CloseWith{
				ConnectionId: c.PublicId,
				BytesUp:      1,
				BytesDown:    2,
				ClosedReason: ConnectionClosedByUser,
			})
		}
		return cw
	}
	tests := []struct {
		name        string
		closeWith   []CloseWith
		reason      TerminationReason
		wantErr     bool
		wantIsError errors.Code
	}{
		{
			name:      "valid",
			closeWith: setupFn(2),
			reason:    ClosedByUser,
		},
		{
			name:        "empty-closed-with",
			closeWith:   []CloseWith{},
			reason:      ClosedByUser,
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "missing-ConnectionId",
			closeWith: func() []CloseWith {
				cw := setupFn(2)
				cw[1].ConnectionId = ""
				return cw
			}(),
			reason:      ClosedByUser,
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			resp, err := connRepo.closeConnections(context.Background(), tt.closeWith)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(len(tt.closeWith), len(resp))
			for _, r := range resp {
				require.NotNil(r.Connection)
				require.NotNil(r.ConnectionState)
				assert.Equal(StatusClosed, r.ConnectionState)
			}
		})
	}
}

func TestUpdateBytesUpDown(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)

	rw := db.New(conn)
	ctx := context.Background()

	sessRepo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Create session.
	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	s, _, err = sessRepo.ActivateSession(context.Background(), s.PublicId, s.Version, TestTofu(t))
	require.NoError(t, err)

	// Create some connections.
	connCount := 5
	conns := make([]*Connection, 0, connCount)
	for i := 0; i < connCount; i++ {
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
		c.BytesUp = rand.Int63()
		c.BytesDown = rand.Int63()
		conns = append(conns, c)
	}

	// Update bytes up and down.
	require.NoError(t, connRepo.updateBytesUpBytesDown(ctx, conns...))

	// Assert that the bytes up and down values have been persisted.
	for i := 0; i < len(conns); i++ {
		c, err := connRepo.LookupConnection(ctx, conns[i].GetPublicId())
		require.NoError(t, err)

		require.Equal(t, conns[i].BytesUp, c.BytesUp)
		require.Equal(t, conns[i].BytesDown, c.BytesDown)
	}

	// Close all connections
	closeReasons := []ClosedReason{
		UnknownReason,
		ConnectionTimedOut,
		ConnectionClosedByUser,
		ConnectionCanceled,
		ConnectionNetworkError,
		ConnectionSystemError,
	}
	cws := make([]CloseWith, 0, len(conns))
	for i := 0; i < len(conns); i++ {
		conns[i].ClosedReason = closeReasons[rand.Intn(len(closeReasons))].String()
		cr, err := convertToClosedReason(ctx, conns[i].ClosedReason)
		require.NoError(t, err)

		cws = append(cws, CloseWith{
			ConnectionId: conns[i].GetPublicId(),
			BytesUp:      conns[i].BytesUp,
			BytesDown:    conns[i].BytesDown,
			ClosedReason: cr,
		})
	}
	_, err = connRepo.closeConnections(ctx, cws)
	require.NoError(t, err)

	// Attempt to update bytes up and bytes down.
	conns2 := make([]*Connection, len(conns))
	for i := 0; i < len(conns); i++ {
		conns2[i] = conns[i].Clone().(*Connection)
		conns2[i].BytesUp = rand.Int63()
		conns2[i].BytesDown = rand.Int63()
	}
	require.NoError(t, connRepo.updateBytesUpBytesDown(ctx, conns2...))

	// BytesUp and BytesDown values should be set to the old ones.
	for i := 0; i < len(conns); i++ {
		c, err := connRepo.LookupConnection(ctx, conns[i].GetPublicId())
		require.NoError(t, err)

		require.Equal(t, conns[i].BytesUp, c.BytesUp)
		require.Equal(t, conns[i].BytesDown, c.BytesDown)
	}
}

func TestRepository_StateTransitions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	s := TestDefaultSession(t, conn, wrapper, iamRepo)
	tofu := TestTofu(t)
	_, _, err = repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
	require.NoError(t, err)

	// First connection will transition authorized -> connected -> closed
	c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
	cw := ConnectWith{
		ConnectionId:       c.PublicId,
		ClientTcpAddress:   "127.0.0.1",
		ClientTcpPort:      22,
		EndpointTcpAddress: "127.0.0.1",
		EndpointTcpPort:    2222,
		UserClientIp:       "127.0.0.1",
	}
	gotConn, err := connRepo.LookupConnection(context.Background(), c.PublicId)
	require.NoError(t, err)
	require.NotNil(t, gotConn)
	require.Equal(t, StatusAuthorized, ConnectionStatusFromString(gotConn.Status))

	_, err = connRepo.ConnectConnection(context.Background(), cw)
	require.NoError(t, err)

	gotConn, err = connRepo.LookupConnection(context.Background(), c.PublicId)
	require.NoError(t, err)
	require.NotNil(t, gotConn)
	require.Equal(t, StatusConnected, ConnectionStatusFromString(gotConn.Status))

	// Attempt to connect again, expect failure
	_, err = connRepo.ConnectConnection(context.Background(), cw)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid state transition from connected")

	closeWith := CloseWith{
		ConnectionId: c.PublicId,
		ClosedReason: ConnectionClosedByUser,
	}
	resp, err := connRepo.closeConnections(context.Background(), []CloseWith{closeWith})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, StatusClosed, resp[0].ConnectionState)

	// Second connection will transition from authorized -> closed
	c2 := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")

	gotConn, err = connRepo.LookupConnection(context.Background(), c2.PublicId)
	require.NoError(t, err)
	require.NotNil(t, gotConn)
	require.Equal(t, StatusAuthorized, ConnectionStatusFromString(gotConn.Status))

	closeWith2 := CloseWith{
		ConnectionId: c2.PublicId,
		ClosedReason: ConnectionClosedByUser,
	}
	resp, err = connRepo.closeConnections(context.Background(), []CloseWith{closeWith2})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, StatusClosed, resp[0].ConnectionState)
	gotConn, err = connRepo.LookupConnection(context.Background(), c2.PublicId)
	require.NoError(t, err)
	require.NotNil(t, gotConn)
	require.Equal(t, StatusClosed, ConnectionStatusFromString(gotConn.Status))

	// Now try to connect it while closed and ensure it can't transition to connected
	cw2 := ConnectWith{
		ConnectionId:       c2.PublicId,
		ClientTcpAddress:   "127.0.0.1",
		ClientTcpPort:      22,
		EndpointTcpAddress: "127.0.0.1",
		EndpointTcpPort:    2222,
		UserClientIp:       "127.0.0.1",
	}
	_, err = connRepo.ConnectConnection(context.Background(), cw2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid state transition from closed")

	gotConn, err = connRepo.LookupConnection(context.Background(), c2.PublicId)
	require.NoError(t, err)
	require.NotNil(t, gotConn)
	require.Equal(t, StatusClosed, ConnectionStatusFromString(gotConn.Status))
}
