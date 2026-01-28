// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package dbtest_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestGenerateSessionBenchmarkTemplateDumps is not really a test, it uses
// the testing framework for easy access to a boundary server for
// populating a database with test data. This database is then dumped
// to predictable files for use in benchmarking.
//
// Each database dump contains:
//   - N number of sessions, with each session having M connections.
//   - P users, each owning an even amount of the sessions. All users
//     use the password "testpassword" to login.
//
// It is safe for users of these dumps to assume all of this, for the variables
// N, M and P defined in the "scenarios" struct below.
func TestGenerateSessionBenchmarkTemplateDumps(t *testing.T) {
	if os.Getenv("BOUNDARY_DB_TEST_GENERATE_SESSION_BENCHMARK_TEMPLATE_DUMPS") == "" {
		t.Skip("BOUNDARY_DB_TEST_GENERATE_SESSION_BENCHMARK_TEMPLATE_DUMPS is not set")
		return
	}

	pgDumpBinary := "pg_dump"
	if os.Getenv("PGDUMP_BINARY") != "" {
		pgDumpBinary = os.Getenv("PGDUMP_BINARY")
	}
	_, err := exec.LookPath(pgDumpBinary)
	require.NoError(t, err, "failed to find %s, please install it to generate benchmarking template dumps. Set PGDUMP_BINARY to configure a custom binary name", pgDumpBinary)

	// Verify that the version of pg_dump used to create the dumps is the
	// same as the LOWEST version of Postgres that we support, since dumps are
	// only forward compatible, not backwards compatible, and we want to be able
	// to import these dumps into all the versions of Postgres that we support.
	out, err := exec.Command(pgDumpBinary, "--version").Output()
	require.NoError(t, err, "failed to check pg_dump version")
	major, _, err := parsePgDumpVersion(string(out))
	require.NoError(t, err, "failed to parse pg_dump version")
	if major != 11 {
		t.Fatal("pg_dump version is not 11, please install pg_dump 11 to generate benchmarking template dumps")
	}

	scenarios := []struct {
		sessions        int
		connsPerSession int
		users           int
	}{
		{
			sessions:        1000,
			connsPerSession: 10,
			users:           10,
		},
		{
			sessions:        1000,
			connsPerSession: 10,
			users:           25,
		},
		{
			sessions:        1000,
			connsPerSession: 10,
			users:           50,
		},
		{
			sessions:        1000,
			connsPerSession: 10,
			users:           75,
		},
		{
			sessions:        1000,
			connsPerSession: 10,
			users:           100,
		},
		{
			sessions:        1000,
			connsPerSession: 10,
			users:           500,
		},
	}

	// Create a global semaphore to limit the number of concurrent requests
	// across all tests.
	semaphore := make(chan struct{}, runtime.NumCPU())
	for _, scenario := range scenarios {
		scenario := scenario // Parallel test closures act as goroutines, copy iteration variable
		t.Run(fmt.Sprintf("Generate-%d-sessions-%d-conns-per-session-%d-users-dump", scenario.sessions, scenario.connsPerSession, scenario.users), func(t *testing.T) {
			t.Parallel() // Lets speed things up a bit
			ctx := context.Background()
			require := require.New(t)
			outputPath := fmt.Sprintf("./docker/benchmark_dumps/session_%d_%d_%d.dump", scenario.sessions, scenario.connsPerSession, scenario.users)
			if _, err := os.Lstat(outputPath); err == nil {
				t.Skipf("%q already exists, skipping", path.Base(outputPath))
				return
			}
			conn, dbURL := db.TestSetup(t, "postgres")
			rw := db.New(conn)
			wrap, err := dbtest.GetBoundaryBenchmarksRootKeyWrapper(ctx)
			require.NoError(err)
			kms := kms.TestKms(t, conn, wrap)

			iamRepo := iam.TestRepo(t, conn, wrap)
			authTokenRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			pwRepo, err := password.NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			sessRepo, err := session.NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			connRepo, err := session.NewConnectionRepository(ctx, rw, rw, kms)
			require.NoError(err)
			_ = server.TestKmsWorker(t, conn, wrap)

			usersStart := time.Now()
			t.Logf("Populating %d users", scenario.users)
			users := make([]*user, scenario.users)
			eg, gCtx := errgroup.WithContext(ctx)
			for i := 0; i < scenario.users; i++ {
				i := i
				// Parallelize user creation
				eg.Go(func() error {
					select {
					case semaphore <- struct{}{}:
					case <-gCtx.Done():
						return gCtx.Err()
					}
					defer func() {
						select {
						case <-semaphore:
						case <-gCtx.Done():
						}
					}()
					users[i] = newUser(t, gCtx, iamRepo, authTokenRepo, pwRepo, kms, conn, "user"+strconv.Itoa(i))
					return nil
				})
			}
			require.NoError(eg.Wait())
			t.Logf("Populated %d users in %s", scenario.users, time.Since(usersStart))

			insertStart := time.Now()
			t.Logf("Populating %d sessions", scenario.sessions)
			eg, gCtx = errgroup.WithContext(ctx)
			for i := 0; i < scenario.sessions; i++ {
				i := i
				userIndex := i % len(users)
				// Parallelize session creation
				eg.Go(func() error {
					select {
					case semaphore <- struct{}{}:
					case <-gCtx.Done():
						return gCtx.Err()
					}
					defer func() {
						select {
						case <-semaphore:
							if i > 0 && i%(scenario.sessions/4) == 0 {
								t.Logf("%d%% done in %s", 100*i/scenario.sessions, time.Since(insertStart))
							}
						case <-gCtx.Done():
						}
					}()
					sess := session.TestSession(t, conn, wrap, session.ComposedOf{
						UserId:      users[userIndex].id,
						HostId:      users[userIndex].hostId,
						TargetId:    users[userIndex].targetId,
						HostSetId:   users[userIndex].hostSetId,
						AuthTokenId: users[userIndex].authTokenId,
						ProjectId:   users[userIndex].scopeId,
						Endpoint:    "tcp://127.0.0.1:22",
					})
					cycleSessionStates(t, ctx, sess, sessRepo, connRepo, conn, scenario.connsPerSession)
					return nil
				})
			}
			require.NoError(eg.Wait())
			_, err = sessRepo.TerminateCompletedSessions(ctx)
			require.NoError(err)
			t.Logf("Populated %d sessions in %s", scenario.sessions, time.Since(insertStart))

			dumpStart := time.Now()
			t.Logf("Dumping %d sessions to %s", scenario.sessions, outputPath)
			cmd := exec.Command(
				pgDumpBinary,
				"--format=c", // Set custom postgres format for faster restore
				"--file="+outputPath,
				dbURL,
			)
			out, err := cmd.CombinedOutput()
			require.NoError(err, string(out))
			t.Logf("Dumped %d sessions to %s in %s", scenario.sessions, outputPath, time.Since(dumpStart))
		})
	}
}

func cycleSessionStates(t testing.TB, ctx context.Context, sess *session.Session, sessRepo *session.Repository, connRepo *session.ConnectionRepository, conn *db.DB, numConns int) {
	sess, _, err := sessRepo.ActivateSession(ctx, sess.PublicId, sess.Version, []byte(`tofu`))
	require.NoError(t, err)
	var closeWiths []session.CloseWith
	for i := 0; i < numConns; i++ {
		connID := session.TestConnection(t, conn, sess.PublicId, "127.0.0.1", 22, "127.0.0.2", 23, "127.0.0.1").PublicId
		closeWiths = append(closeWiths, session.CloseWith{ConnectionId: connID, ClosedReason: session.ConnectionCanceled})
	}
	// Cancel 50% of the sessions
	if rand.Intn(2) == 0 {
		_, err = sessRepo.CancelSession(ctx, sess.PublicId, sess.Version)
		require.NoError(t, err)
		_, err = session.CloseConnections(ctx, sessRepo, connRepo, closeWiths)
		require.NoError(t, err)
	}
}

func parsePgDumpVersion(in string) (int, int, error) {
	var major, minor int
	_, err := fmt.Sscanf(in, "pg_dump (PostgreSQL) %d.%d", &major, &minor)
	if err != nil {
		return 0, 0, err
	}
	return major, minor, nil
}

type user struct {
	id          string
	hostId      string
	targetId    string
	hostSetId   string
	authTokenId string
	scopeId     string
}

func newUser(t testing.TB, ctx context.Context, iamRepo *iam.Repository, authTokenRepo *authtoken.Repository, pwRepo *password.Repository, kms *kms.Kms, conn *db.DB, name string) *user {
	require := require.New(t)
	o, pWithSessions := iam.TestScopes(t, iamRepo)
	am := password.TestAuthMethod(t, conn, o.GetPublicId())
	acct, err := password.NewAccount(ctx, am.GetPublicId(), password.WithLoginName(name))
	require.NoError(err)
	acct, err = pwRepo.CreateAccount(ctx, o.PublicId, acct, password.WithPassword(dbtest.BoundaryBenchmarksUserPassword))
	require.NoError(err)
	u := iam.TestUser(t, iamRepo, o.GetPublicId(), iam.WithAccountIds(acct.PublicId), iam.WithName(name))
	at, err := authTokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	require.NoError(err)
	require.Equal(name, u.Name)
	hc := static.TestCatalogs(t, conn, pWithSessions.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, pWithSessions.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	return &user{
		id:          u.GetPublicId(),
		hostId:      h.GetPublicId(),
		targetId:    tar.GetPublicId(),
		hostSetId:   hs.GetPublicId(),
		authTokenId: at.GetPublicId(),
		scopeId:     pWithSessions.GetPublicId(),
	}
}
