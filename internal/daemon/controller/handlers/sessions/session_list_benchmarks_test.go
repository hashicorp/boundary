package sessions_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type template struct {
	name            string
	sessions        int
	connsPerSession int
	users           int
}

func BenchmarkSessionList(b *testing.B) {
	// See the explanation in testing/dbtest/session_list_benchmarks_dump_generation_test.go for
	// an overview of the assumptions made when creating these template scenarios.
	for _, template := range []template{
		{
			name:            dbtest.Boundary1000Sessions10ConnsPerSession10Template,
			sessions:        1000,
			connsPerSession: 10,
			users:           10,
		},
		{
			name:            dbtest.Boundary1000Sessions10ConnsPerSession25Template,
			sessions:        1000,
			connsPerSession: 10,
			users:           25,
		},
		{
			name:            dbtest.Boundary1000Sessions10ConnsPerSession50Template,
			sessions:        1000,
			connsPerSession: 10,
			users:           50,
		},
		{
			name:            dbtest.Boundary1000Sessions10ConnsPerSession75Template,
			sessions:        1000,
			connsPerSession: 10,
			users:           75,
		},
		{
			name:            dbtest.Boundary1000Sessions10ConnsPerSession100Template,
			sessions:        1000,
			connsPerSession: 10,
			users:           100,
		},
		{
			name:            dbtest.Boundary1000Sessions10ConnsPerSession500Template,
			sessions:        1000,
			connsPerSession: 10,
			users:           500,
		},
	} {
		b.Run(fmt.Sprintf("%d_sessions_%d_conns_per_session_%d_users", template.sessions, template.connsPerSession, template.users), func(b *testing.B) {
			ctx := context.Background()
			conn, _ := db.TestSetup(b, "postgres", db.WithTemplate(template.name))
			rw := db.New(conn)
			kmsThing, err := kms.New(ctx, rw, rw)
			require.NoError(b, err)
			wrap, err := dbtest.GetBoundaryBenchmarksRootKeyWrapper(ctx)
			require.NoError(b, err)
			err = kmsThing.AddExternalWrappers(ctx, kms.WithRootWrapper(wrap))
			require.NoError(b, err)

			iamRepo, err := iam.NewRepository(rw, rw, kmsThing)
			require.NoError(b, err)

			sessRepo, err := session.NewRepository(rw, rw, kmsThing)
			require.NoError(b, err)

			authTokenRepo, err := authtoken.NewRepository(rw, rw, kmsThing)
			require.NoError(b, err)

			pwRepo, err := password.NewRepository(rw, rw, kmsThing)
			require.NoError(b, err)

			serversRepo, err := server.NewRepository(rw, rw, kmsThing)
			require.NoError(b, err)

			iamRepoFn := func() (*iam.Repository, error) {
				return iamRepo, nil
			}
			sessRepoFn := func() (*session.Repository, error) {
				return sessRepo, nil
			}
			authTokenRepoFn := func() (*authtoken.Repository, error) {
				return authTokenRepo, nil
			}
			serversRepoFn := func() (*server.Repository, error) {
				return serversRepo, nil
			}

			s, err := sessions.NewService(sessRepoFn, iamRepoFn)
			require.NoError(b, err)

			var users []*userWithToken
			rows, err := rw.Query(ctx, "select public_id from iam_user where name like 'user%'", nil)
			require.NoError(b, err)
			var userId string
			for rows.Next() {
				err = rows.Scan(&userId)
				require.NoError(b, err)
				require.NotEmpty(b, userId)
				u, accountIds, err := iamRepo.LookupUser(ctx, userId)
				require.NoError(b, err)
				require.NotEmpty(b, accountIds)
				account, err := pwRepo.LookupAccount(ctx, accountIds[0])
				require.NoError(b, err)
				require.NotNil(b, account)
				acct, err := pwRepo.Authenticate(ctx, u.ScopeId, account.AuthMethodId, u.Name, dbtest.BoundaryBenchmarksUserPassword)
				require.NoError(b, err)
				require.NotNil(b, acct)
				tok, err := authTokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
				require.NoError(b, err)
				require.NotEmpty(b, tok)
				tokString, err := authtoken.EncryptToken(ctx, kmsThing, u.ScopeId, tok.PublicId, tok.Token)
				require.NoError(b, err)
				req := &pbs.ListSessionsRequest{
					ScopeId:   scope.Global.String(),
					Recursive: true,
					Filter:    fmt.Sprintf(`"/item/user_id"==%q`, u.PublicId),
				}
				ctx := auth.NewVerifierContext(
					ctx,
					iamRepoFn,
					authTokenRepoFn,
					serversRepoFn,
					kmsThing,
					&authpb.RequestInfo{
						PublicId:       tok.PublicId,
						EncryptedToken: tokString,
						TokenFormat:    uint32(auth.AuthTokenTypeBearer),
					})
				users = append(users, &userWithToken{
					User: u,
					req:  req,
					ctx:  ctx,
				})
			}
			require.NoError(b, rows.Close())
			require.NoError(b, rows.Err())
			require.Len(b, users, template.users)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				eg := &errgroup.Group{}
				for i := range users {
					user := users[i]
					eg.Go(func() error {
						_, err := s.ListSessions(user.ctx, user.req)
						if err != nil {
							return fmt.Errorf("list failed: %s", err.Error())
						}
						return nil
					})
				}
				require.NoError(b, eg.Wait())
			}
		})
	}
}

type userWithToken struct {
	*iam.User
	req *pbs.ListSessionsRequest
	ctx context.Context
}
