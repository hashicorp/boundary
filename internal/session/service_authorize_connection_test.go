// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_AuthorizeConnection(t *testing.T) {
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

	var testServer string
	setupFn := func(exp *timestamp.Timestamp) *Session {
		composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
		if exp != nil {
			composedOf.ExpirationTime = exp
		}
		s := TestSession(t, conn, wrapper, composedOf)
		srv := server.TestKmsWorker(t, conn, wrapper)
		testServer = srv.PublicId
		tofu := TestTofu(t)
		_, _, err := repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
		require.NoError(t, err)
		return s
	}
	testSession := setupFn(nil)

	tests := []struct {
		name          string
		session       *Session
		wantErr       bool
		wantIsError   error
		wantAuthzInfo AuthzSummary
	}{
		{
			name:    "valid",
			session: testSession,
			wantAuthzInfo: AuthzSummary{
				ConnectionLimit:        -1,
				CurrentConnectionCount: 1,
				ExpirationTime:         testSession.ExpirationTime,
			},
		},
		{
			name: "empty-sessionId",
			session: func() *Session {
				s := AllocSession()
				return &s
			}(),
			wantErr: true,
		},
		{
			name: "exceeded-connection-limit",
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

				// Create connection against the session so that any further attempts are declined
				_ = TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
				return session
			}(),
			wantErr: true,
		},
		{
			name:    "expired-session",
			session: setupFn(&timestamp.Timestamp{Timestamp: timestamppb.Now()}),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			c, authzInfo, err := AuthorizeConnection(context.Background(), repo, connRepo, tt.session.PublicId, testServer)
			if tt.wantErr {
				require.Error(err)
				// TODO (jimlambrt 9/2020): add in tests for errorsIs once we
				// remove the grpc errors from the repo.
				// if tt.wantIsError != nil {
				// 	assert.Truef(errors.Is(err, tt.wantIsError), "unexpected error %s", err.Error())
				// }
				return
			}
			require.NoError(err)
			require.NotNil(c)
			require.NotNil(c.Status)
			assert.Equal(StatusAuthorized, ConnectionStatusFromString(c.Status))

			assert.True(authzInfo.ExpirationTime.GetTimestamp().AsTime().Sub(tt.wantAuthzInfo.ExpirationTime.GetTimestamp().AsTime()) < 10*time.Millisecond)
			tt.wantAuthzInfo.ExpirationTime = authzInfo.ExpirationTime

			assert.Equal(tt.wantAuthzInfo.ExpirationTime, authzInfo.ExpirationTime)
			assert.Equal(tt.wantAuthzInfo.ConnectionLimit, authzInfo.ConnectionLimit)
			assert.Equal(tt.wantAuthzInfo.CurrentConnectionCount, authzInfo.CurrentConnectionCount)
		})
	}
}
