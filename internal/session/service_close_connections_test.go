// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestServiceCloseConnections(t *testing.T) {
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

	type sessionAndCloseWiths struct {
		session   *Session
		closeWith []CloseWith
	}

	setupFn := func(cnt int, addtlConn int) sessionAndCloseWiths {
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
		s := TestSession(t, conn, wrapper, composedOf, WithExpirationTime(exp))
		tofu := TestTofu(t)
		s, _, err = repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
		require.NoError(t, err)

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

		for i := 0; i < addtlConn; i++ {
			TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
			require.NoError(t, err)
		}
		return sessionAndCloseWiths{s, cw}
	}

	tests := []struct {
		name              string
		sessionCW         sessionAndCloseWiths
		wantClosedSession bool
	}{
		{
			name:              "close-multiple-connections-and-session",
			sessionCW:         setupFn(4, 0),
			wantClosedSession: true,
		},
		{
			name:              "close-subset-of-connections",
			sessionCW:         setupFn(2, 1),
			wantClosedSession: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			resp, err := CloseConnections(ctx, repo, connRepo, tt.sessionCW.closeWith)
			require.NoError(err)

			for _, r := range resp {
				require.NotNil(r.Connection)
				require.NotNil(r.ConnectionState)
				assert.Equal(StatusClosed, r.ConnectionState)
			}

			// Ensure session is in the state we want- terminated if all conns closed, else active
			ses, _, err := repo.LookupSession(ctx, tt.sessionCW.session.PublicId)
			require.NoError(err)
			if tt.wantClosedSession {
				assert.Equal(StatusTerminated, ses.States[0].Status)
			} else {
				assert.Equal(StatusActive, ses.States[0].Status)
			}
		})
	}
}
