package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceCloseConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	type sessionAndCloseWiths struct {
		session   *Session
		closeWith []CloseWith
	}

	setupFn := func(cnt int, addtlConn int) sessionAndCloseWiths {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		srv := TestWorker(t, conn, wrapper)
		tofu := TestTofu(t)
		s, _, err = repo.ActivateSession(context.Background(), s.PublicId, s.Version, srv.PrivateId, srv.Type, tofu)
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
				require.NotNil(r.ConnectionStates)
				assert.Equal(StatusClosed, r.ConnectionStates[0].Status)
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
