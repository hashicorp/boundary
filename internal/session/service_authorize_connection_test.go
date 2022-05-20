package session

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/servers"
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
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	var testServer string
	setupFn := func(exp *timestamp.Timestamp) *Session {
		composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
		if exp != nil {
			composedOf.ExpirationTime = exp
		}
		s := TestSession(t, conn, wrapper, composedOf)
		srv := servers.TestWorker(t, conn, wrapper)
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
				ConnectionLimit:        1,
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
				session := setupFn(nil)
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

			c, cs, authzInfo, err := AuthorizeConnection(context.Background(), repo, connRepo, tt.session.PublicId, testServer)
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
			require.NotNil(cs)
			assert.Equal(StatusAuthorized, cs[0].Status)

			assert.True(authzInfo.ExpirationTime.GetTimestamp().AsTime().Sub(tt.wantAuthzInfo.ExpirationTime.GetTimestamp().AsTime()) < 10*time.Millisecond)
			tt.wantAuthzInfo.ExpirationTime = authzInfo.ExpirationTime

			assert.Equal(tt.wantAuthzInfo.ExpirationTime, authzInfo.ExpirationTime)
			assert.Equal(tt.wantAuthzInfo.ConnectionLimit, authzInfo.ConnectionLimit)
			assert.Equal(tt.wantAuthzInfo.CurrentConnectionCount, authzInfo.CurrentConnectionCount)
		})
	}
}
