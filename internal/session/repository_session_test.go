// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	authtokenStore "github.com/hashicorp/boundary/internal/authtoken/store"
	cred "github.com/hashicorp/boundary/internal/credential"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	staticStore "github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	iamStore "github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	tcpStore "github.com/hashicorp/boundary/internal/target/tcp/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/jackc/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRepository_ListSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	listPerms := &perms.UserPermissions{
		UserId: composedOf.UserId,
		Permissions: []perms.Permission{
			{
				ScopeId:  composedOf.ProjectId,
				Resource: resource.Session,
				Action:   action.List,
			},
		},
	}
	type args struct {
		opt []Option
	}
	tests := []struct {
		name            string
		createCnt       int
		args            args
		perms           *perms.UserPermissions
		wantCnt         int
		wantErr         bool
		withConnections int
	}{
		{
			name:      "no-limit",
			createCnt: testLimit + 1,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			perms:   listPerms,
			wantCnt: testLimit + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: testLimit + 1,
			args:      args{},
			perms:     listPerms,
			wantCnt:   testLimit,
			wantErr:   false,
		},
		{
			name:      "custom-limit",
			createCnt: testLimit + 1,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			perms:   listPerms,
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "withNoPerms",
			createCnt: testLimit + 1,
			args:      args{},
			perms:     &perms.UserPermissions{},
			wantCnt:   0,
			wantErr:   false,
		},
		{
			name:      "withPermsDifferentScopeId",
			createCnt: testLimit + 1,
			args:      args{},
			perms: &perms.UserPermissions{
				Permissions: []perms.Permission{
					{
						ScopeId:  "o_thisIsNotValid",
						Resource: resource.Session,
						Action:   action.List,
					},
				},
			},
			wantCnt: 0,
			wantErr: false,
		},
		{
			name:      "withPermsNonListAction",
			createCnt: testLimit + 1,
			args:      args{},
			perms: &perms.UserPermissions{
				Permissions: []perms.Permission{
					{
						ScopeId:  composedOf.ProjectId,
						Resource: resource.Session,
						Action:   action.Read,
					},
				},
			},
			wantCnt: 0,
			wantErr: false,
		},
		{
			name:            "multiple-connections",
			createCnt:       testLimit + 1,
			args:            args{},
			perms:           listPerms,
			wantCnt:         testLimit,
			wantErr:         false,
			withConnections: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			repo, err := NewRepository(ctx, rw, rw, kms, WithLimit(testLimit), WithPermissions(tt.perms))
			require.NoError(err)

			db.TestDeleteWhere(t, conn, func() any { i := AllocSession(); return &i }(), "1=1")
			testSessions := []*Session{}
			for i := 0; i < tt.createCnt; i++ {
				s := TestSession(t, conn, wrapper, composedOf)
				_ = TestState(t, conn, s.PublicId, StatusActive)
				testSessions = append(testSessions, s)
				for i := 0; i < tt.withConnections; i++ {
					_ = TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.2", 23, "127.0.0.1")
				}
			}
			assert.Equal(tt.createCnt, len(testSessions))
			got, err := repo.ListSessions(context.Background(), tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
			for i := 0; i < len(got); i++ {
				// connections should not be returned for list requests
				assert.Equal(0, len(got[i].Connections))
				for _, c := range got[i].Connections {
					assert.Equal("127.0.0.1", c.ClientTcpAddress)
					assert.Equal(uint32(22), c.ClientTcpPort)
					assert.Equal("127.0.0.2", c.EndpointTcpAddress)
					assert.Equal(uint32(23), c.EndpointTcpPort)
				}
			}
			if tt.wantCnt > 0 {
				assert.Equal(StatusActive, got[0].States[0].Status)
				assert.Equal(StatusPending, got[0].States[1].Status)
			}
		})
	}
	t.Run("withOrder", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db.TestDeleteWhere(t, conn, func() any { i := AllocSession(); return &i }(), "1=1")
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestSession(t, conn, wrapper, composedOf)
		}

		repo, err := NewRepository(ctx, rw, rw, kms, WithLimit(testLimit), WithPermissions(listPerms))
		require.NoError(err)

		got, err := repo.ListSessions(context.Background(), WithOrderByCreateTime(db.AscendingOrderBy))
		require.NoError(err)
		assert.Equal(wantCnt, len(got))

		for i := 0; i < len(got)-1; i++ {
			first := got[i].CreateTime.Timestamp.AsTime()
			second := got[i+1].CreateTime.Timestamp.AsTime()
			assert.True(first.Before(second))
		}
	})
	t.Run("onlySelf", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db.TestDeleteWhere(t, conn, func() any { i := AllocSession(); return &i }(), "1=1")
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestSession(t, conn, wrapper, composedOf)
		}
		s := TestDefaultSession(t, conn, wrapper, iamRepo)

		p := &perms.UserPermissions{
			UserId: s.UserId,
			Permissions: []perms.Permission{
				{
					ScopeId:  s.ProjectId,
					Resource: resource.Session,
					Action:   action.List,
					OnlySelf: true,
				},
			},
		}
		repo, err := NewRepository(ctx, rw, rw, kms, WithLimit(testLimit), WithPermissions(p))
		require.NoError(err)
		got, err := repo.ListSessions(context.Background(), WithUserId(s.UserId))
		require.NoError(err)
		assert.Equal(1, len(got))
		assert.Equal(s.UserId, got[0].UserId)
	})
}

func TestRepository_ListSessions_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()

	db.TestDeleteWhere(t, conn, func() any { i := AllocSession(); return &i }(), "1=1")

	const numPerScope = 10
	var p []perms.Permission
	for i := 0; i < numPerScope; i++ {
		composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
		p = append(p, perms.Permission{
			ScopeId:  composedOf.ProjectId,
			Resource: resource.Session,
			Action:   action.List,
		})
		s := TestSession(t, conn, wrapper, composedOf)
		_ = TestState(t, conn, s.PublicId, StatusActive)
	}

	repo, err := NewRepository(ctx, rw, rw, kms, WithPermissions(&perms.UserPermissions{
		Permissions: p,
	}))
	require.NoError(t, err)
	got, err := repo.ListSessions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, len(p), len(got))
}

func TestRepository_CreateSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	worker := server.TestKmsWorker(t, conn, wrapper)

	workerAddresses := []string{"1.2.3.4"}
	type args struct {
		composedOf      ComposedOf
		workerAddresses []string
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantIsError errors.Code
	}{
		{
			name: "valid",
			args: args{
				composedOf:      TestSessionParams(t, conn, wrapper, iamRepo),
				workerAddresses: workerAddresses,
			},
			wantErr: false,
		},
		{
			name: "valid-with-credentials",
			args: args{
				composedOf:      testSessionCredentialParams(t, conn, wrapper, iamRepo),
				workerAddresses: workerAddresses,
			},
			wantErr: false,
		},
		{
			name: "valid-static-address",
			args: args{
				composedOf:      TestSessionTargetAddressParams(t, conn, wrapper, iamRepo),
				workerAddresses: workerAddresses,
			},
			wantErr: false,
		},
		{
			name: "valid-with-protocol-worker",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ProtocolWorkerId = worker.PublicId
					return c
				}(),
				workerAddresses: workerAddresses,
			},
		},
		{
			name: "invalid-protocol-worker",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ProtocolWorkerId = "something"
					return c
				}(),
				workerAddresses: workerAddresses,
			},
			wantErr:     true,
			wantIsError: errors.CheckConstraint,
		},
		{
			name: "empty-host-source-endpoint",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.HostId = ""
					c.HostSetId = ""
					c.Endpoint = ""
					return c
				}(),
				workerAddresses: workerAddresses,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-userId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.UserId = ""
					return c
				}(),
				workerAddresses: workerAddresses,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-targetId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.TargetId = ""
					return c
				}(),
				workerAddresses: workerAddresses,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-authTokenId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.AuthTokenId = ""
					return c
				}(),
				workerAddresses: workerAddresses,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-projectId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ProjectId = ""
					return c
				}(),
				workerAddresses: workerAddresses,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-worker-addresses",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					return c
				}(),
				workerAddresses: nil,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-expiration-time",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ExpirationTime = nil
					return c
				}(),
				workerAddresses: nil,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "zero-expiration-time",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ExpirationTime = timestamp.New(time.Time{})
					return c
				}(),
				workerAddresses: nil,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wrapper wrapping.Wrapper
			if tt.args.composedOf.ProjectId != "" {
				wrapper, err = kmsCache.GetWrapper(context.Background(), tt.args.composedOf.ProjectId, kms.KeyPurposeSessions)
				require.NoError(t, err)
			}

			assert, require := assert.New(t), require.New(t)
			s := &Session{
				UserId:             tt.args.composedOf.UserId,
				HostId:             tt.args.composedOf.HostId,
				TargetId:           tt.args.composedOf.TargetId,
				HostSetId:          tt.args.composedOf.HostSetId,
				AuthTokenId:        tt.args.composedOf.AuthTokenId,
				ProjectId:          tt.args.composedOf.ProjectId,
				Endpoint:           tt.args.composedOf.Endpoint,
				ExpirationTime:     tt.args.composedOf.ExpirationTime,
				ConnectionLimit:    tt.args.composedOf.ConnectionLimit,
				DynamicCredentials: tt.args.composedOf.DynamicCredentials,
				StaticCredentials:  tt.args.composedOf.StaticCredentials,
				ProtocolWorkerId:   tt.args.composedOf.ProtocolWorkerId,
			}
			ses, err := repo.CreateSession(context.Background(), wrapper, s, tt.args.workerAddresses)

			if tt.wantErr {
				assert.Error(err)
				assert.Nil(ses)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			require.NoError(err)
			assert.NotNil(ses)
			assert.NotNil(ses.CertificatePrivateKey)
			assert.NotNil(ses.States)
			assert.NotNil(ses.CreateTime)
			assert.NotNil(ses.States[0].StartTime)
			assert.Equal(ses.States[0].Status, StatusPending)
			keyId, err := wrapper.KeyId(context.Background())
			require.NoError(err)
			assert.Equal(keyId, ses.KeyId)
			assert.Len(ses.DynamicCredentials, len(s.DynamicCredentials))
			assert.Len(ses.StaticCredentials, len(s.StaticCredentials))
			foundSession, _, err := repo.LookupSession(context.Background(), ses.PublicId)
			require.NoError(err)
			assert.Equal(keyId, foundSession.KeyId)

			// Account for slight offsets in nanos
			assert.True(foundSession.ExpirationTime.Timestamp.AsTime().Sub(ses.ExpirationTime.Timestamp.AsTime()) < time.Second)
			ses.ExpirationTime = foundSession.ExpirationTime

			assert.Equal(ses, foundSession)

			err = db.TestVerifyOplog(t, rw, ses.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)

			require.Equal(1, len(foundSession.States))
			assert.Equal(foundSession.States[0].Status, StatusPending)
			assert.Equal(s.DynamicCredentials, foundSession.DynamicCredentials)
			for _, cred := range foundSession.DynamicCredentials {
				assert.Empty(cred.CredentialId)
				assert.NotEmpty(cred.SessionId)
				assert.NotEmpty(cred.LibraryId)
				assert.NotEmpty(cred.CredentialPurpose)
			}

			assert.Equal(s.StaticCredentials, foundSession.StaticCredentials)
			for _, cred := range foundSession.StaticCredentials {
				assert.NotEmpty(cred.CredentialStaticId)
				assert.NotEmpty(cred.SessionId)
				assert.NotEmpty(cred.CredentialPurpose)
			}
		})
	}
}

func TestRepository_updateState(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	tests := []struct {
		name                   string
		session                *Session
		newStatus              Status
		overrideSessionId      *string
		overrideSessionVersion *uint32
		wantStateCnt           int
		wantErr                bool
		wantIsError            errors.Code
	}{
		{
			name:         "canceling",
			session:      TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus:    StatusCanceling,
			wantStateCnt: 2,
			wantErr:      false,
		},
		{
			name: "closed",
			session: func() *Session {
				s := TestDefaultSession(t, conn, wrapper, iamRepo)
				_ = TestState(t, conn, s.PublicId, StatusActive)
				return s
			}(),
			newStatus:    StatusTerminated,
			wantStateCnt: 3,
			wantErr:      false,
		},
		{
			name:      "bad-version",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: StatusCanceling,
			overrideSessionVersion: func() *uint32 {
				v := uint32(22)
				return &v
			}(),
			wantErr: true,
		},
		{
			name:      "empty-version",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: StatusCanceling,
			overrideSessionVersion: func() *uint32 {
				v := uint32(0)
				return &v
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name:      "bad-sessionId",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: StatusCanceling,
			overrideSessionId: func() *string {
				s := "s_thisIsNotValid"
				return &s
			}(),
			wantErr: true,
		},
		{
			name:      "empty-session",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: StatusCanceling,
			overrideSessionId: func() *string {
				s := ""
				return &s
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var id string
			var version uint32
			switch {
			case tt.overrideSessionId != nil:
				id = *tt.overrideSessionId
			default:
				id = tt.session.PublicId
			}
			switch {
			case tt.overrideSessionVersion != nil:
				version = *tt.overrideSessionVersion
			default:
				version = tt.session.Version
			}

			s, ss, err := repo.updateState(context.Background(), id, version, tt.newStatus)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(ss)
			assert.Equal(tt.wantStateCnt, len(ss))
			assert.Equal(tt.newStatus, ss[0].Status)
		})
	}
}

func TestRepository_transitionState(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	tofu := TestTofu(t)

	tests := []struct {
		name        string
		session     *Session
		states      []Status
		wantErr     []bool
		wantIsError errors.Code
	}{
		{
			name:    "full valid state transition",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			states: []Status{
				StatusPending, StatusActive, StatusCanceling, StatusTerminated,
			},
			wantErr: []bool{false, false, false, false},
		},
		{
			name:    "partial valid state transition- 1",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			states: []Status{
				StatusPending, StatusActive, StatusTerminated,
			},
			wantErr: []bool{false, false, false, false},
		},
		{
			name:    "partial valid state transition- 2",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			states: []Status{
				StatusPending, StatusCanceling, StatusTerminated,
			},
			wantErr: []bool{false, false, false},
		},
		{
			name:    "invalid state transition - 1",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			states: []Status{
				StatusPending, StatusCanceling, StatusTerminated, StatusActive,
			},
			wantErr: []bool{false, false, false, true},
		},
		{
			name:    "invalid state transition - 2",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			states: []Status{
				StatusPending, StatusCanceling, StatusActive,
			},
			wantErr: []bool{false, false, true},
		},
		{
			name:    "invalid state transition - 3",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			states: []Status{
				StatusPending, StatusTerminated, StatusActive,
			},
			wantErr: []bool{false, false, true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			id := tt.session.PublicId
			version := tt.session.Version
			for i, status := range tt.states {
				var s *Session
				var ss []*State
				var err error
				if status == StatusActive {
					s, ss, err = repo.ActivateSession(context.Background(), id, version, tofu)
				} else {
					s, ss, err = repo.updateState(context.Background(), id, version, status)
				}
				if tt.wantErr[i] {
					require.Error(err)
					assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
					return
				}
				require.NoError(err)
				require.NotNil(s)
				require.NotNil(ss)
				assert.Equal(status, ss[0].Status)
				version = s.Version
			}
		})
	}
}

func TestRepository_TerminateCompletedSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	setupFn := func(t testing.TB, limit int32, expireIn time.Duration, leaveOpen bool) *Session {
		require.NotEqualf(t, int32(0), limit, "setupFn: limit cannot be zero")
		exp := timestamppb.New(time.Now().Add(expireIn))
		composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
		composedOf.ConnectionLimit = limit
		composedOf.ExpirationTime = &timestamp.Timestamp{Timestamp: exp}
		s := TestSession(t, conn, wrapper, composedOf)

		tofu := TestTofu(t)
		s, _, err = repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
		require.NoError(t, err)
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 222, "127.0.0.1")
		if !leaveOpen {
			cw := CloseWith{
				ConnectionId: c.PublicId,
				BytesUp:      1,
				BytesDown:    1,
				ClosedReason: ConnectionClosedByUser,
			}
			_, err = connRepo.closeConnections(context.Background(), []CloseWith{cw})
			require.NoError(t, err)
		}
		return s
	}

	type testArgs struct {
		sessions   []*Session
		wantTermed map[string]TerminationReason
	}
	tests := []struct {
		name    string
		setup   func(testing.TB) testArgs
		wantErr bool
	}{
		{
			name: "sessions-with-closed-connections",
			setup: func(t testing.TB) testArgs {
				cnt := 1
				wantTermed := map[string]TerminationReason{}
				sessions := make([]*Session, 0, 5)
				for i := 0; i < cnt; i++ {
					// make one with closed connections
					s := setupFn(t, 1, time.Hour+1, false)
					wantTermed[s.PublicId] = ConnectionLimit
					sessions = append(sessions, s)

					// make one with connection left open
					s2 := setupFn(t, 1, time.Hour+1, true)
					sessions = append(sessions, s2)
				}
				return testArgs{
					sessions:   sessions,
					wantTermed: wantTermed,
				}
			},
		},
		{
			name: "sessions-with-open-and-closed-connections",
			setup: func(t testing.TB) testArgs {
				cnt := 5
				wantTermed := map[string]TerminationReason{}
				sessions := make([]*Session, 0, 5)
				for i := 0; i < cnt; i++ {
					// make one with closed connections
					s := setupFn(t, 2, time.Hour+1, false)
					_ = TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 222, "127.0.0.1")
					sessions = append(sessions, s)
					wantTermed[s.PublicId] = ConnectionLimit
				}
				return testArgs{
					sessions:   sessions,
					wantTermed: nil,
				}
			},
		},
		{
			name: "sessions-with-no-connections",
			setup: func(t testing.TB) testArgs {
				cnt := 5
				sessions := make([]*Session, 0, 5)
				for i := 0; i < cnt; i++ {
					s := TestDefaultSession(t, conn, wrapper, iamRepo)
					sessions = append(sessions, s)
				}
				return testArgs{
					sessions:   sessions,
					wantTermed: nil,
				}
			},
		},
		{
			name: "sessions-with-open-connections",
			setup: func(t testing.TB) testArgs {
				cnt := 5
				sessions := make([]*Session, 0, 5)
				for i := 0; i < cnt; i++ {
					s := setupFn(t, 1, time.Hour+1, true)
					sessions = append(sessions, s)
				}
				return testArgs{
					sessions:   sessions,
					wantTermed: nil,
				}
			},
		},
		{
			name: "expired-sessions",
			setup: func(t testing.TB) testArgs {
				cnt := 5
				wantTermed := map[string]TerminationReason{}
				sessions := make([]*Session, 0, 5)
				for i := 0; i < cnt; i++ {
					// make one with closed connections
					s := setupFn(t, 1, time.Millisecond+1, false)
					// make one with connection left open
					s2 := setupFn(t, 1, time.Millisecond+1, true)
					sessions = append(sessions, s, s2)
					wantTermed[s.PublicId] = TimedOut
				}
				return testArgs{
					sessions:   sessions,
					wantTermed: wantTermed,
				}
			},
		},
		{
			name: "canceled-sessions-with-closed-connections",
			setup: func(t testing.TB) testArgs {
				cnt := 1
				wantTermed := map[string]TerminationReason{}
				sessions := make([]*Session, 0, 5)
				for i := 0; i < cnt; i++ {
					// make one with limit of 3 and closed connections
					s := setupFn(t, 3, time.Hour+1, false)
					wantTermed[s.PublicId] = SessionCanceled
					sessions = append(sessions, s)

					// make one with connection left open
					s2 := setupFn(t, 1, time.Hour+1, true)
					sessions = append(sessions, s2)

					// now cancel the sessions
					for _, ses := range sessions {
						_, err := repo.CancelSession(context.Background(), ses.PublicId, ses.Version)
						require.NoError(t, err)
					}
				}
				return testArgs{
					sessions:   sessions,
					wantTermed: wantTermed,
				}
			},
		},
		{
			name: "sessions-with-unlimited-connections",
			setup: func(t testing.TB) testArgs {
				cnt := 5
				wantTermed := map[string]TerminationReason{}
				sessions := make([]*Session, 0, 5)
				for i := 0; i < cnt; i++ {
					// make one with unlimited connections
					s := setupFn(t, -1, time.Hour+1, false)
					// make one with limit of one all connections closed
					s2 := setupFn(t, 1, time.Hour+1, false)
					sessions = append(sessions, s, s2)
					wantTermed[s2.PublicId] = ConnectionLimit
				}
				return testArgs{
					sessions:   sessions,
					wantTermed: wantTermed,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { i := AllocSession(); return &i }(), "1=1")
			args := tt.setup(t)

			got, err := repo.TerminateCompletedSessions(context.Background())
			if tt.wantErr {
				require.Error(err)
				return
			}
			assert.NoError(err)
			t.Logf("terminated: %d", got)
			var foundTerminated int
			for _, ses := range args.sessions {
				found, _, err := repo.LookupSession(context.Background(), ses.PublicId)
				require.NoError(err)
				_, shouldBeTerminated := args.wantTermed[found.PublicId]
				if shouldBeTerminated {
					if found.TerminationReason != "" {
						foundTerminated += 1
					}
					assert.Equal(args.wantTermed[found.PublicId].String(), found.TerminationReason)
					t.Logf("terminated %s has a connection limit of %d", found.PublicId, found.ConnectionLimit)
					conn, err := connRepo.ListConnectionsBySessionId(context.Background(), found.PublicId)
					require.NoError(err)
					for _, sc := range conn {
						c, cs, err := connRepo.LookupConnection(context.Background(), sc.PublicId)
						require.NoError(err)
						assert.NotEmpty(c.ClosedReason)
						for _, s := range cs {
							t.Logf("%s session %s connection state %s at %s", found.PublicId, s.ConnectionId, s.Status, s.EndTime)
						}
					}
				} else {
					t.Logf("not terminated %s has a connection limit of %d", found.PublicId, found.ConnectionLimit)
					assert.Equal("", found.TerminationReason)
					conn, err := connRepo.ListConnectionsBySessionId(context.Background(), found.PublicId)
					require.NoError(err)
					for _, sc := range conn {
						cs, err := fetchConnectionStates(context.Background(), rw, sc.PublicId)
						require.NoError(err)
						for _, s := range cs {
							t.Logf("%s session %s connection state %s at %s", found.PublicId, s.ConnectionId, s.Status, s.EndTime)
						}
					}
				}
			}
			assert.Equal(len(args.wantTermed), foundTerminated)
		})
	}
}

func TestRepository_CancelSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	setupFn := func() *Session {
		session := TestDefaultSession(t, conn, wrapper, iamRepo)
		_ = TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
		return session
	}
	tests := []struct {
		name                   string
		session                *Session
		overrideSessionId      *string
		overrideSessionVersion *uint32
		wantErr                bool
		wantIsError            errors.Code
		wantStatus             Status
	}{
		{
			name:       "valid",
			session:    setupFn(),
			wantStatus: StatusCanceling,
		},
		{
			name: "already-terminated",
			session: func() *Session {
				future := timestamppb.New(time.Now().Add(time.Hour))
				exp := &timestamp.Timestamp{Timestamp: future}
				org, proj := iam.TestScopes(t, iamRepo)

				cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
				hosts := static.TestHosts(t, conn, cats[0].PublicId, 1)
				sets := static.TestSets(t, conn, cats[0].PublicId, 1)
				_ = static.TestSetMembers(t, conn, sets[0].PublicId, hosts)

				// We need to set the session connection limit to 1 so that the session
				// is terminated when the one connection is closed.
				tcpTarget := tcp.TestTarget(ctx, t, conn, proj.PublicId, "test target", target.WithSessionConnectionLimit(1))

				targetRepo, err := target.NewRepository(ctx, rw, rw, testKms)
				require.NoError(t, err)
				_, err = targetRepo.AddTargetHostSources(ctx, tcpTarget.GetPublicId(), tcpTarget.GetVersion(), []string{sets[0].PublicId})
				require.NoError(t, err)

				authMethod := password.TestAuthMethods(t, conn, org.PublicId, 1)[0]
				acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "name1")
				user := iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(acct.PublicId))

				authTokenRepo, err := authtoken.NewRepository(ctx, rw, rw, testKms)
				require.NoError(t, err)
				at, err := authTokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)

				expTime := timestamppb.Now()
				expTime.Seconds += int64(tcpTarget.GetSessionMaxSeconds())
				composedOf := ComposedOf{
					UserId:          user.PublicId,
					HostId:          hosts[0].PublicId,
					TargetId:        tcpTarget.GetPublicId(),
					HostSetId:       sets[0].PublicId,
					AuthTokenId:     at.PublicId,
					ProjectId:       tcpTarget.GetProjectId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ExpirationTime:  &timestamp.Timestamp{Timestamp: expTime},
					ConnectionLimit: tcpTarget.GetSessionConnectionLimit(),
				}
				session := TestSession(t, conn, wrapper, composedOf, WithExpirationTime(exp))
				c := TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
				cw := CloseWith{
					ConnectionId: c.PublicId,
					BytesUp:      1,
					BytesDown:    1,
					ClosedReason: ConnectionClosedByUser,
				}
				_, err = CloseConnections(ctx, repo, connRepo, []CloseWith{cw})
				require.NoError(t, err)
				s, _, err := repo.LookupSession(ctx, session.PublicId)
				require.NoError(t, err)
				assert.Equal(t, StatusTerminated, s.States[0].Status)
				// The two transactions to cancel connections and terminate the session will result in version being 2, not 1
				session.Version = s.Version
				return session
			}(),
			wantStatus: StatusTerminated,
		},
		{
			name:    "bad-session-id",
			session: setupFn(),
			overrideSessionId: func() *string {
				id, err := newId(ctx)
				require.NoError(t, err)
				return &id
			}(),
			wantErr:    true,
			wantStatus: StatusCanceling,
		},
		{
			name:    "missing-session-id",
			session: setupFn(),
			overrideSessionId: func() *string {
				id := ""
				return &id
			}(),
			wantStatus:  StatusCanceling,
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name:    "bad-version-id",
			session: setupFn(),
			overrideSessionVersion: func() *uint32 {
				v := uint32(101)
				return &v
			}(),
			wantStatus: StatusCanceling,
			wantErr:    true,
		},
		{
			name:    "missing-version-id",
			session: setupFn(),
			overrideSessionVersion: func() *uint32 {
				v := uint32(0)
				return &v
			}(),
			wantStatus:  StatusCanceling,
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var id string
			var version uint32
			switch {
			case tt.overrideSessionId != nil:
				id = *tt.overrideSessionId
			default:
				id = tt.session.PublicId
			}
			switch {
			case tt.overrideSessionVersion != nil:
				version = *tt.overrideSessionVersion
			default:
				version = tt.session.Version
			}
			s, err := repo.CancelSession(ctx, id, version)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(s.States)
			assert.Equal(tt.wantStatus, s.States[0].Status)

			stateCnt := len(s.States)
			origStartTime := s.States[0].StartTime
			// check idempontency
			s2, err := repo.CancelSession(context.Background(), id, version+1)
			require.NoError(err)
			require.NotNil(s2)
			require.NotNil(s2.States)
			assert.Equal(stateCnt, len(s2.States))
			assert.Equal(tt.wantStatus, s.States[0].Status)
			assert.Equal(origStartTime, s2.States[0].StartTime)
		})
	}
}

func TestRepository_CancelSessionViaFKNull(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	setupFn := func() *Session {
		session := TestDefaultSession(t, conn, wrapper, iamRepo)
		_ = TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
		return session
	}
	type cancelFk struct {
		s      *Session
		fkType any
	}
	tests := []struct {
		name     string
		cancelFk cancelFk
	}{
		{
			name: "UserId",
			cancelFk: func() cancelFk {
				s := setupFn()
				t := &iam.User{
					User: &iamStore.User{
						PublicId: s.UserId,
					},
				}
				return cancelFk{
					s:      s,
					fkType: t,
				}
			}(),
		},
		{
			name: "Host",
			cancelFk: func() cancelFk {
				s := setupFn()

				t := &static.Host{
					Host: &staticStore.Host{
						PublicId: s.HostId,
					},
				}
				return cancelFk{
					s:      s,
					fkType: t,
				}
			}(),
		},
		{
			name: "Target",
			cancelFk: func() cancelFk {
				s := setupFn()

				t := &tcp.Target{
					Target: &tcpStore.Target{
						PublicId: s.TargetId,
					},
				}
				return cancelFk{
					s:      s,
					fkType: t,
				}
			}(),
		},
		{
			name: "Scope",
			cancelFk: func() cancelFk {
				s := setupFn()

				t := &iam.Scope{
					Scope: &iamStore.Scope{
						PublicId: s.ProjectId,
					},
				}
				return cancelFk{
					s:      s,
					fkType: t,
				}
			}(),
		},
		{
			name: "HostSet",
			cancelFk: func() cancelFk {
				s := setupFn()

				t := &static.HostSet{
					HostSet: &staticStore.HostSet{
						PublicId: s.HostSetId,
					},
				}
				return cancelFk{
					s:      s,
					fkType: t,
				}
			}(),
		},
		{
			name: "AuthToken",
			cancelFk: func() cancelFk {
				s := setupFn()

				t := &authtoken.AuthToken{
					AuthToken: &authtokenStore.AuthToken{
						PublicId: s.AuthTokenId,
					},
				}
				// override the table name so we can delete this thing, since
				// it's default table name is a non-writable view.
				t.SetTableName("auth_token")
				return cancelFk{
					s:      s,
					fkType: t,
				}
			}(),
		},
		{
			name: "canceled-only-once",
			cancelFk: func() cancelFk {
				s := setupFn()
				h := &static.Host{
					Host: &staticStore.Host{
						PublicId: s.HostId,
					},
				}

				var err error
				s, err = repo.CancelSession(context.Background(), s.PublicId, s.Version)
				require.NoError(t, err)
				require.Equal(t, StatusCanceling, s.States[0].Status)
				return cancelFk{
					s:      s,
					fkType: h,
				}
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, _, err := repo.LookupSession(context.Background(), tt.cancelFk.s.PublicId, WithIgnoreDecryptionFailures(true))
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(s.States)

			rowsDeleted, err := rw.Delete(context.Background(), tt.cancelFk.fkType)
			if err != nil {
				var pgError *pgconn.PgError
				if errors.As(err, &pgError) {
					t.Log(pgError.Message)
					t.Log(pgError.Detail)
					t.Log(pgError.Where)
					t.Log(pgError.ConstraintName)
					t.Log(pgError.TableName)
				}
			}
			require.NoError(err)
			require.Equal(1, rowsDeleted)

			s, _, err = repo.LookupSession(context.Background(), tt.cancelFk.s.PublicId, WithIgnoreDecryptionFailures(true))
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(s.States)
			assert.Equal(StatusCanceling, s.States[0].Status)
			canceledCnt := 0
			for _, ss := range s.States {
				if ss.Status == StatusCanceling {
					canceledCnt += 1
				}
			}
			assert.Equal(1, canceledCnt)
		})
	}
}

func TestRepository_ActivateSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	tofu := TestTofu(t)
	tests := []struct {
		name                   string
		session                *Session
		overrideSessionId      *string
		overrideSessionVersion *uint32
		wantErr                bool
		wantIsError            errors.Code
	}{
		{
			name:    "valid",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			wantErr: false,
		},
		{
			name: "already-active",
			session: func() *Session {
				s := TestDefaultSession(t, conn, wrapper, iamRepo)
				activeSession, _, err := repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
				require.NoError(t, err)
				return activeSession
			}(),
			wantErr: true,
		},
		{
			name:    "bad-session-id",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionId: func() *string {
				id, err := newId(ctx)
				require.NoError(t, err)
				return &id
			}(),
			wantErr: true,
		},
		{
			name:    "bad-session-version",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionVersion: func() *uint32 {
				v := uint32(100)
				return &v
			}(),
			wantErr: true,
		},
		{
			name:    "empty-session-id",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionId: func() *string {
				id := ""
				return &id
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name:    "empty-session-version",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionVersion: func() *uint32 {
				v := uint32(0)
				return &v
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var id string
			var version uint32
			switch {
			case tt.overrideSessionId != nil:
				id = *tt.overrideSessionId
			default:
				id = tt.session.PublicId
			}
			switch {
			case tt.overrideSessionVersion != nil:
				version = *tt.overrideSessionVersion
			default:
				version = tt.session.Version
			}
			s, ss, err := repo.ActivateSession(context.Background(), id, version, tofu)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(ss)
			assert.Equal(tofu, s.TofuToken)
			assert.Equal(2, len(ss))
			assert.Equal(StatusActive, ss[0].Status)
		})
		t.Run("already active", func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			session := TestDefaultSession(t, conn, wrapper, iamRepo)
			s, ss, err := repo.ActivateSession(context.Background(), session.PublicId, 1, tofu)
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(ss)
			assert.Equal(2, len(ss))
			assert.Equal(StatusActive, ss[0].Status)

			_, _, err = repo.ActivateSession(context.Background(), session.PublicId, 1, tofu)
			require.Error(err)

			_, _, err = repo.ActivateSession(context.Background(), session.PublicId, 2, tofu)
			require.Error(err)
		})
	}
}

func TestRepository_DeleteSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	type args struct {
		session *Session
		opt     []Option
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
				session: TestDefaultSession(t, conn, wrapper, iamRepo),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				session: func() *Session {
					s := AllocSession()
					return &s
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "session.(Repository).DeleteSession: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				session: func() *Session {
					s := TestDefaultSession(t, conn, wrapper, iamRepo)
					id, err := newId(ctx)
					require.NoError(t, err)
					s.PublicId = id
					return s
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
			deletedRows, err := repo.DeleteSession(context.Background(), tt.args.session.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.session.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundSession, _, err := repo.LookupSession(context.Background(), tt.args.session.PublicId)
			assert.NoError(err)
			assert.Nil(foundSession)

			err = db.TestVerifyOplog(t, rw, tt.args.session.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
		})
	}
}

func testSessionCredentialParams(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository) ComposedOf {
	t.Helper()
	params := TestSessionParams(t, conn, wrapper, iamRepo)
	require := require.New(t)
	rw := db.New(conn)

	ctx := context.Background()

	kms := kms.TestKms(t, conn, wrapper)
	targetRepo, err := target.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	tar, err := targetRepo.LookupTarget(ctx, params.TargetId)
	require.NoError(err)
	require.NotNil(tar)

	vaultStore := vault.TestCredentialStores(t, conn, wrapper, params.ProjectId, 1)[0]
	libIds := vault.TestCredentialLibraries(t, conn, wrapper, vaultStore.GetPublicId(), 2)

	staticStore := credstatic.TestCredentialStore(t, conn, wrapper, params.ProjectId)
	upCreds := credstatic.TestUsernamePasswordCredentials(t, conn, wrapper, "u", "p", staticStore.GetPublicId(), params.ProjectId, 2)

	ids := target.CredentialSources{
		BrokeredCredentialIds: []string{libIds[0].GetPublicId(), libIds[1].GetPublicId(), upCreds[0].GetPublicId(), upCreds[1].GetPublicId()},
	}
	_, err = targetRepo.AddTargetCredentialSources(ctx, tar.GetPublicId(), tar.GetVersion(), ids)
	require.NoError(err)
	dynamicCreds := []*DynamicCredential{
		NewDynamicCredential(libIds[0].GetPublicId(), cred.BrokeredPurpose),
		NewDynamicCredential(libIds[1].GetPublicId(), cred.BrokeredPurpose),
	}
	params.DynamicCredentials = dynamicCreds

	staticCreds := []*StaticCredential{
		NewStaticCredential(upCreds[0].GetPublicId(), cred.BrokeredPurpose),
		NewStaticCredential(upCreds[1].GetPublicId(), cred.BrokeredPurpose),
	}
	params.StaticCredentials = staticCreds
	return params
}

func TestRepository_deleteTargetFKey(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	targetRepo, err := target.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	tests := []struct {
		name  string
		state Status
	}{
		{
			name:  "Delete target for terminated session",
			state: StatusTerminated,
		},
		{
			name:  "Delete target for canceling session",
			state: StatusCanceling,
		},
		{
			name:  "Delete target for active session",
			state: StatusActive,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			c := TestSessionParams(t, conn, wrapper, iamRepo)
			sesh := TestSession(t, conn, wrapper, c)

			s := TestState(t, conn, sesh.PublicId, tt.state)
			assert.Equal(tt.state, s.Status)

			// Delete target associated with session; ensure target deletion with no state violations
			rows, err := targetRepo.DeleteTarget(context.Background(), c.TargetId)
			require.NoError(err)
			assert.Equal(1, rows)
			foundSession, _, err := repo.LookupSession(context.Background(), sesh.PublicId)
			assert.NoError(err)
			assert.Empty(foundSession.TargetId)
		})
	}
}

func TestRepository_deleteTerminated(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	cases := []struct {
		sessionCount   int
		terminateCount int
		threshold      time.Duration
		expected       int
	}{
		{
			0,
			0,
			time.Nanosecond,
			0,
		},
		{
			1,
			1,
			time.Nanosecond,
			1,
		},
		{
			1,
			1,
			time.Hour,
			0,
		},
		{
			10,
			10,
			time.Nanosecond,
			10,
		},
		{
			10,
			4,
			time.Nanosecond,
			4,
		},
		{
			10,
			0,
			time.Nanosecond,
			0,
		},
		{
			10,
			10,
			time.Hour,
			0,
		},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_%d_%s", tc.sessionCount, tc.terminateCount, tc.threshold), func(t *testing.T) {
			t.Cleanup(func() {
				sdb, err := conn.SqlDB(ctx)
				require.NoError(t, err)
				_, err = sdb.Exec(`delete from session;`)
				require.NoError(t, err)
			})

			for i := 0; i < tc.sessionCount; i++ {
				s := TestSession(t, conn, wrapper, composedOf)
				if i < tc.terminateCount {
					_, err = repo.CancelSession(ctx, s.PublicId, s.Version)
					require.NoError(t, err)
				}

			}
			c, err := repo.TerminateCompletedSessions(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.terminateCount, c)

			c, err = repo.deleteSessionsTerminatedBefore(ctx, tc.threshold)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, c)
		})
	}
}

func Test_decryptAndMaybeUpdateSession(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsRepo := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	ctx := context.Background()

	t.Run("errors-with-invalid-kms", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		err := decryptAndMaybeUpdateSession(ctx, nil, s, rw)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session", func(t *testing.T) {
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, nil, rw)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-writer", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, s, nil)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-project-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.ProjectId = ""
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-key-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.KeyId = ""
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-user-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.UserId = ""
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-public-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.PublicId = ""
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.Error(t, err)
	})
	t.Run("session-with-local-session-key-succeeds", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.NoError(t, err)
	})
	t.Run("session-with-derived-session-key-succeeds", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.CtCertificatePrivateKey = nil
		s.CertificatePrivateKey = nil
		s.TofuToken = nil
		s.CtTofuToken = nil
		err := decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.NoError(t, err)
	})
	t.Run("session-with-derived-session-key-and-tofu-token-succeeds", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.CtCertificatePrivateKey = nil
		s.CertificatePrivateKey = nil
		s.TofuToken = []byte("A token")
		actualKeyId := s.KeyId
		databaseWrapper, err := kmsRepo.GetWrapper(ctx, s.ProjectId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		err = s.encrypt(ctx, databaseWrapper)
		require.NoError(t, err)
		s.KeyId = actualKeyId // Restore this as the encrypt call above will overwrite it.
		err = decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.NoError(t, err)
	})
	t.Run("session-with-derived-session-key-and-tofu-token-cannot-be-decrypted", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.CtCertificatePrivateKey = nil
		s.CertificatePrivateKey = nil
		s.TofuToken = []byte("A token")
		actualKeyId := s.KeyId
		databaseWrapper, err := kmsRepo.GetWrapper(ctx, s.ProjectId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		err = s.encrypt(ctx, databaseWrapper)
		require.NoError(t, err)
		databaseKeyId := s.KeyId
		err = kmsRepo.RotateKeys(ctx, s.ProjectId)
		require.NoError(t, err)
		ok, err := kmsRepo.DestroyKeyVersion(ctx, s.ProjectId, databaseKeyId)
		require.NoError(t, err)
		assert.True(t, ok)
		s.KeyId = actualKeyId // Restore this as the encrypt call above will overwrite it.
		err = decryptAndMaybeUpdateSession(ctx, kmsRepo, s, rw)
		require.ErrorContains(t, err, "You may need to recreate your session")
	})
}

func TestRepository_CheckIfNoLongerActive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	testKms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	terminatedSession := TestDefaultSession(t, conn, wrapper, iamRepo)
	terminatedSession, err = repo.CancelSession(ctx, terminatedSession.PublicId, terminatedSession.Version)
	require.NoError(t, err)
	n, err := repo.terminateSessionIfPossible(ctx, terminatedSession.PublicId)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	cancelingSess := TestDefaultSession(t, conn, wrapper, iamRepo)
	cancelingSess, err = repo.CancelSession(ctx, cancelingSess.PublicId, cancelingSess.Version)
	require.NoError(t, err)

	pendingSess := TestDefaultSession(t, conn, wrapper, iamRepo)

	activeSess := TestDefaultSession(t, conn, wrapper, iamRepo)
	_, _, err = repo.ActivateSession(ctx, activeSess.PublicId, activeSess.Version, []byte("tofu"))
	require.NoError(t, err)

	unrecognizedSessionId := "unrecognized_session_id"
	got, err := repo.CheckIfNotActive(ctx, []string{unrecognizedSessionId, terminatedSession.PublicId, cancelingSess.PublicId, activeSess.PublicId, pendingSess.PublicId})
	assert.NoError(t, err)
	var gotIds []string
	for _, g := range got {
		gotIds = append(gotIds, g.SessionId)
	}
	assert.ElementsMatch(t, gotIds, []string{unrecognizedSessionId, terminatedSession.PublicId, cancelingSess.PublicId})
}
