// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
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
	"github.com/hashicorp/go-uuid"
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
				GrantScopeId: composedOf.ProjectId,
				Resource:     resource.Session,
				Action:       action.List,
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
		wantTTime       time.Time
		withConnections int
	}{
		{
			name:      "default-limit",
			createCnt: testLimit + 1,
			args:      args{},
			perms:     listPerms,
			wantCnt:   testLimit,
			wantErr:   false,
			wantTTime: time.Now(),
		},
		{
			name:      "custom-limit",
			createCnt: testLimit + 1,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			perms:     listPerms,
			wantCnt:   3,
			wantErr:   false,
			wantTTime: time.Now(),
		},
		{
			name:      "withNoPerms",
			createCnt: testLimit + 1,
			args:      args{},
			perms:     &perms.UserPermissions{},
			wantCnt:   0,
			wantErr:   false,
			wantTTime: time.Time{},
		},
		{
			name:      "withPermsDifferentScopeId",
			createCnt: testLimit + 1,
			args:      args{},
			perms: &perms.UserPermissions{
				Permissions: []perms.Permission{
					{
						GrantScopeId: "o_thisIsNotValid",
						Resource:     resource.Session,
						Action:       action.List,
					},
				},
			},
			wantCnt:   0,
			wantErr:   false,
			wantTTime: time.Now(),
		},
		{
			name:      "withPermsNonListAction",
			createCnt: testLimit + 1,
			args:      args{},
			perms: &perms.UserPermissions{
				Permissions: []perms.Permission{
					{
						GrantScopeId: composedOf.ProjectId,
						Resource:     resource.Session,
						Action:       action.Read,
					},
				},
			},
			wantCnt:   0,
			wantErr:   false,
			wantTTime: time.Time{},
		},
		{
			name:            "multiple-connections",
			createCnt:       testLimit + 1,
			args:            args{},
			perms:           listPerms,
			wantCnt:         testLimit,
			wantErr:         false,
			withConnections: 3,
			wantTTime:       time.Now(),
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
			got, ttime, err := repo.listSessions(ctx, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(tt.wantTTime.Before(ttime.Add(10 * time.Second)))
			assert.True(tt.wantTTime.After(ttime.Add(-10 * time.Second)))
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
					GrantScopeId: s.ProjectId,
					Resource:     resource.Session,
					Action:       action.List,
					OnlySelf:     true,
				},
			},
		}
		repo, err := NewRepository(ctx, rw, rw, kms, WithLimit(testLimit), WithPermissions(p))
		require.NoError(err)
		got, ttime, err := repo.listSessions(ctx, WithUserId(s.UserId))
		require.NoError(err)
		assert.Equal(1, len(got))
		assert.Equal(s.UserId, got[0].UserId)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db.TestDeleteWhere(t, conn, func() any { i := AllocSession(); return &i }(), "1=1")

		composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

		listPerms := &perms.UserPermissions{
			UserId: composedOf.UserId,
			Permissions: []perms.Permission{
				{
					GrantScopeId: composedOf.ProjectId,
					Resource:     resource.Session,
					Action:       action.List,
				},
			},
		}

		for i := 0; i < 10; i++ {
			_ = TestSession(t, conn, wrapper, composedOf)
		}

		repo, err := NewRepository(ctx, rw, rw, kms, WithPermissions(listPerms))
		require.NoError(err)
		page1, ttime, err := repo.listSessions(ctx, WithLimit(2))
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime, err := repo.listSessions(ctx, WithLimit(2), WithStartPageAfterItem(page1[1]))
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime, err := repo.listSessions(ctx, WithLimit(2), WithStartPageAfterItem(page2[1]))
		require.NoError(err)
		require.Len(page3, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, ttime, err := repo.listSessions(ctx, WithLimit(2), WithStartPageAfterItem(page3[1]))
		require.NoError(err)
		require.Len(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, ttime, err := repo.listSessions(ctx, WithLimit(2), WithStartPageAfterItem(page4[1]))
		require.NoError(err)
		require.Len(page5, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, ttime, err := repo.listSessions(ctx, WithLimit(2), WithStartPageAfterItem(page5[1]))
		require.NoError(err)
		require.Empty(page6)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		// Cancel the first two sessions in lieu of updating
		_, err = repo.CancelSession(ctx, page1[0].PublicId, page1[0].Version)
		require.NoError(err)
		_, err = repo.CancelSession(ctx, page1[1].PublicId, page1[1].Version)
		require.NoError(err)

		// since it will return newest to oldest, we get page1[1] first
		page7, ttime, err := repo.listSessionsRefresh(
			ctx,
			time.Now().Add(-1*time.Second),
			WithLimit(1),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), page1[1].GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		page8, ttime, err := repo.listSessionsRefresh(
			context.Background(),
			time.Now().Add(-1*time.Second),
			WithLimit(1),
			WithStartPageAfterItem(page7[0]),
		)
		require.NoError(err)
		require.Len(page8, 1)
		require.Equal(page8[0].GetPublicId(), page1[0].GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
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
			GrantScopeId: composedOf.ProjectId,
			Resource:     resource.Session,
			Action:       action.List,
		})
		s := TestSession(t, conn, wrapper, composedOf)
		_ = TestState(t, conn, s.PublicId, StatusActive)
	}

	repo, err := NewRepository(ctx, rw, rw, kms, WithPermissions(&perms.UserPermissions{
		Permissions: p,
	}))
	require.NoError(t, err)
	got, ttime, err := repo.listSessions(ctx)
	require.NoError(t, err)
	assert.Equal(t, len(p), len(got))
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_listDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	s := TestSession(t, conn, wrapper, composedOf)
	_ = TestState(t, conn, s.PublicId, StatusActive)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a session
	_, err = repo.DeleteSession(ctx, s.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{s.GetPublicId()}, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create a session, expect 1 entries
	s := TestSession(t, conn, wrapper, composedOf)
	_ = TestState(t, conn, s.PublicId, StatusActive)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the target, expect 0 again
	_, err = repo.DeleteSession(ctx, s.GetPublicId())
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
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
			name: "valid-with-correlation-id",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.CorrelationId, err = uuid.GenerateUUID()
					require.NoError(t, err)
					return c
				}(),
				workerAddresses: workerAddresses,
			},
		},
		{
			name: "invalid-correlation-id",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.CorrelationId = "invalid-format"
					return c
				}(),
				workerAddresses: workerAddresses,
			},
			wantErr:     true,
			wantIsError: errors.InvalidTextRepresentation,
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
				CorrelationId:      tt.args.composedOf.CorrelationId,
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
	require.NoError(t, err)
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
						c, err := connRepo.LookupConnection(context.Background(), sc.PublicId)
						require.NoError(err)
						assert.NotEmpty(c.ClosedReason)
						t.Logf("%s session connection state %s", found.PublicId, c.Status)
					}
				} else {
					t.Logf("not terminated %s has a connection limit of %d", found.PublicId, found.ConnectionLimit)
					assert.Equal("", found.TerminationReason)
					conn, err := connRepo.ListConnectionsBySessionId(context.Background(), found.PublicId)
					require.NoError(err)
					for _, sc := range conn {
						c, err := connRepo.LookupConnection(context.Background(), sc.PublicId)
						require.NoError(err)
						t.Logf("%s session connection state %s", found.PublicId, c.Status)
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
	libIds := vault.TestCredentialLibraries(t, conn, wrapper, vaultStore.GetPublicId(), globals.UnspecifiedCredentialType, 2)

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

func Test_decrypt(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsRepo := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	ctx := context.Background()

	t.Run("errors-with-invalid-kms", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		err := decrypt(ctx, nil, s)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session", func(t *testing.T) {
		err := decrypt(ctx, kmsRepo, nil)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-project-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.ProjectId = ""
		err := decrypt(ctx, kmsRepo, s)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-key-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.KeyId = ""
		err := decrypt(ctx, kmsRepo, s)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-user-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.UserId = ""
		err := decrypt(ctx, kmsRepo, s)
		require.Error(t, err)
	})
	t.Run("errors-with-invalid-session-public-id", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		s.PublicId = ""
		err := decrypt(ctx, kmsRepo, s)
		require.Error(t, err)
	})
	t.Run("session-with-local-session-key-succeeds", func(t *testing.T) {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		err := decrypt(ctx, kmsRepo, s)
		require.NoError(t, err)
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

func TestRepository_LookupProxyCertificate(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	iam.TestScopes(t, iam.TestRepo(t, conn, wrapper)) // despite not looking like it, this is necessary for some reason
	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsWrapper, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeSessions)
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	session := TestSession(t, conn, wrapper, ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   proj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	privKeyValue := []byte("fake-private-key")
	certValue := []byte("fake-cert-value")
	cert, err := NewProxyCertificate(ctx, session.PublicId, privKeyValue, certValue)
	require.NoError(t, err)
	require.NotNil(t, cert)

	err = cert.Encrypt(ctx, kmsWrapper)
	require.NoError(t, err)
	err = rw.Create(ctx, cert)
	require.NoError(t, err)
	tests := []struct {
		name            string
		projectId       string
		sessionId       string
		wantNotFound    bool
		wantErr         bool
		wantErrContains string
	}{
		{
			name:      "success-lookup",
			projectId: proj.GetPublicId(),
			sessionId: session.PublicId,
		},
		{
			name:         "not-found",
			projectId:    proj.GetPublicId(),
			sessionId:    "fake-session-not-found",
			wantNotFound: true,
		},
		{
			name:            "missing-public-id",
			sessionId:       session.PublicId,
			wantErr:         true,
			wantErrContains: "missing project id",
		},
		{
			name:            "missing-session-id",
			projectId:       proj.GetPublicId(),
			wantErr:         true,
			wantErrContains: "missing session id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := repo.LookupProxyCertificate(ctx, tt.projectId, tt.sessionId)
			if tt.wantErr {
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			if tt.wantNotFound {
				require.Nil(got)
				return
			}
			require.NotNil(got)
			assert.Equal(got.PrivateKey, privKeyValue)
			assert.Equal(got.Certificate, certValue)
		})
	}
}

func TestRepository_ProxyCertificateDeletion(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	t.Run("Deleting the project deletes the cert", func(t *testing.T) {
		org, proj := iam.TestScopes(t, iamRepo)
		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeSessions)
		require.NoError(t, err)

		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		session := TestSession(t, conn, wrapper, ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   proj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		privKeyValue := []byte("fake-private-key")
		certValue := []byte("fake-cert-value")
		cert, err := NewProxyCertificate(ctx, session.PublicId, privKeyValue, certValue)
		require.NoError(t, err)
		require.NotNil(t, cert)

		err = cert.Encrypt(ctx, kmsWrapper)
		require.NoError(t, err)

		err = rw.Create(ctx, cert)
		require.NoError(t, err)

		// Check that the cert is there
		got, err := repo.LookupProxyCertificate(ctx, proj.GetPublicId(), session.PublicId)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, got.PrivateKey, privKeyValue)
		assert.Equal(t, got.Certificate, certValue)

		n, err := iamRepo.DeleteScope(ctx, proj.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, n, 1)
		got, err = repo.LookupProxyCertificate(ctx, proj.GetPublicId(), session.PublicId)
		require.NoError(t, err)
		require.Nil(t, got)
	})

	// Ensure that if project ID is set to null on a session for a reason other than the scope being
	// removed that the cert is still removed
	t.Run("Null project id on session deletes the cert", func(t *testing.T) {
		org, proj := iam.TestScopes(t, iamRepo)
		kmsWrapper, err := kmsCache.GetWrapper(context.Background(), proj.PublicId, kms.KeyPurposeSessions)
		require.NoError(t, err)

		at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
		tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
		session := TestSession(t, conn, wrapper, ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ProjectId:   proj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		privKeyValue := []byte("fake-private-key")
		certValue := []byte("fake-cert-value")
		cert, err := NewProxyCertificate(ctx, session.PublicId, privKeyValue, certValue)
		require.NoError(t, err)
		require.NotNil(t, cert)

		err = cert.Encrypt(ctx, kmsWrapper)
		require.NoError(t, err)
		err = rw.Create(ctx, cert)
		require.NoError(t, err)

		// Check that the cert is there
		got, err := repo.LookupProxyCertificate(ctx, proj.GetPublicId(), session.PublicId)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, got.PrivateKey, privKeyValue)
		assert.Equal(t, got.Certificate, certValue)

		query := `update session set project_id = null where 
			public_id = @session_id`

		rowsAffected, err := rw.Exec(ctx, query, []any{
			sql.Named("session_id", session.PublicId),
		})
		require.NoError(t, err)
		require.Equal(t, 1, rowsAffected)

		got, err = repo.LookupProxyCertificate(ctx, proj.GetPublicId(), session.PublicId)
		require.NoError(t, err)
		require.Nil(t, got)
	})
}
